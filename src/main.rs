#![forbid(unsafe_code)]

//! Point d'entree : parse `wg-ez serve` | `wg-ez cli ...` et delegue a la lib.
//!
//! La logique partagee vit dans la lib `wgez` (`src/lib.rs`) ; ce binaire ne
//! fait que router les sous-commandes. `serve` fige la config au boot, migre
//! la DB, applique `INIT_*`, monte WireGuard (`down` + `up`), sert l'API en
//! HTTP/1.1 (tokio `current_thread`, 1 worker), fait tourner le cron 60 s et
//! démonte proprement (`wg-quick down`) à l'arrêt.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use wgez::tunnel::Tunnel;
use wgez::web::Backend as _;
use wgez::wg::runner::SystemRunner;

fn usage(program: &str) {
    eprintln!("usage:");
    eprintln!("  {program} serve        demarre le serveur web");
    eprintln!("  {program} cli ...      outils de secours direct-DB (serveur casse)");
}

/// Cree la paire de cles serveur si elle est encore vide (apres le seed).
fn ensure_server_keys(conn: &rusqlite::Connection, iface_name: &str) -> Result<(), String> {
    let mut iface = wgez::store::interface::get(conn, iface_name)
        .map_err(|e| format!("db error: {e}"))?
        .ok_or_else(|| format!("interface row missing for {iface_name}"))?;
    if !iface.private_key.trim().is_empty() && !iface.public_key.trim().is_empty() {
        return Ok(());
    }
    let (privkey, pubkey, _psk) = wgez::web::backend::generate_keypair(&SystemRunner)
        .map_err(|e| format!("keygen error: {e}"))?;
    iface.private_key = privkey;
    iface.public_key = pubkey;
    wgez::store::interface::upsert(conn, &iface).map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

fn run_serve() -> Result<(), String> {
    // INFO uniquement, fixe explicitement pour qu'un futur defaut ne fasse
    // jamais remonter les spans `TraceLayer` de niveau DEBUG (dont le span
    // omet volontairement l'URI, ex. le secret `/cnf/<token>`).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    // Config lue + validee une fois au boot, puis figee.
    let config = wgez::config::AppConfig::load().map_err(|e| format!("config error: {e}"))?;
    let db_path = PathBuf::from(config.db_path.clone());
    let conn = wgez::db::open(&db_path).map_err(|e| format!("db error: {e}"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| format!("db error: {e}"))?;

    // Setup non-interactif (`INIT_ENABLED`) : admin + host/port (+ groupes
    // optionnels DNS/CIDR/AllowedIPs). Sans effet une fois le setup termine.
    if let Some(init) = config.init.clone() {
        let validated = wgez::setup::ValidatedInit {
            username: init.username,
            password: init.password,
            host: init.host,
            port: i64::from(init.port),
            dns: Some(init.dns),
            ipv4_cidr: Some(init.ipv4_cidr.to_string()),
            ipv6_cidr: init.ipv6_cidr.map(|n| n.to_string()),
            allowed_ips: Some(init.allowed_ips),
        };
        let out = wgez::setup::apply_initial_setup(&conn, &validated, &config.wg_interface)
            .map_err(|e| format!("init setup error: {e}"))?;
        if !out.skipped {
            eprintln!("init setup applied");
        }
    }

    wgez::setup::ensure_interface_rows(&conn, &config.wg_interface)
        .map_err(|e| format!("init error: {e}"))?;
    ensure_server_keys(&conn, &config.wg_interface)?;

    // Boot avec firewall actif mais iptables absent : desactive le flag en DB + warn.
    if wgez::web::backend::reconcile_firewall_flag(&conn, &config.wg_interface, config.disable_ipv6)
        .map_err(|e| format!("firewall error: {e}"))?
    {
        eprintln!("warning: firewall disabled: iptables not available");
    }

    // Sequence de boot : ecrit le .conf complet en 0600, `down` (erreur ignoree),
    // `up` (applique tout, pas de `syncconf` apres), rebuild firewall.
    let snap = wgez::web::backend::load_snapshot(
        &conn,
        &config.wg_interface,
        config.disable_ipv4,
        config.disable_ipv6,
    )
    .map_err(|e| format!("tunnel error: {e}"))?;
    let tunnel = Tunnel::new(SystemRunner).with_conf_dir(config.wg_conf_dir.clone());
    if let Err(e) = tunnel.boot(&snap) {
        tracing::warn!("wireguard boot failed (serving anyway): {e}");
        eprintln!("warning: wireguard boot failed (serving anyway): {e}");
    }
    drop(conn);

    let backend = Arc::new(
        wgez::web::backend::SqliteBackend::new(config.clone())
            .map_err(|e| format!("backend error: {e}"))?,
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime error: {e}"))?;
    runtime.block_on(serve(config, backend))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn serve(
    config: wgez::config::AppConfig,
    backend: Arc<wgez::web::backend::SqliteBackend>,
) -> Result<(), String> {
    let locales = wgez::web::Locales::load().map_err(|e| format!("locales error: {e}"))?;
    let state = wgez::web::AppState::new(backend.clone(), locales, config.trusted_proxies.clone());
    let app = wgez::web::build_router(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    eprintln!("listening on {addr}");

    // Cron 60 s : auto-desactivation des clients expires (un `Tunnel::apply`
    // si necessaire) + purge des OTL expires (ne touche jamais WireGuard).
    let cron_backend = backend.clone();
    let on_tick = Arc::new(move |out: wgez::cron::CronOutcome| {
        if out.needs_apply() {
            let backend = cron_backend.clone();
            tokio::spawn(async move {
                if let Err(e) = backend.apply_tunnel().await {
                    tracing::warn!("cron apply failed: {e}");
                }
            });
        }
    });
    let cron = wgez::cron::spawn_cron(PathBuf::from(config.db_path.clone()), on_tick);

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        cron.abort();
        return Err(format!("serve error: {e}"));
    }
    cron.abort();

    // Arret propre : `wg-quick down` + nettoyage des chaines (echecs ignores).
    Tunnel::new(SystemRunner)
        .with_conf_dir(config.wg_conf_dir.clone())
        .shutdown(
            &config.wg_interface,
            config.disable_ipv4,
            config.disable_ipv6,
        );
    Ok(())
}

fn cmd_serve() -> ExitCode {
    match run_serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("serve error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_cli(args: &[String]) -> ExitCode {
    match wgez::cli::parse_cli_args(args) {
        Ok(cmd) => {
            let path = wgez::db::default_path();
            match wgez::cli::run_offline(&path, &cmd) {
                Ok(out) => {
                    print!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cli error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("cli error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let program = match args.first() {
        Some(p) => p.clone(),
        None => "wg-ez".to_string(),
    };
    let rest: &[String] = if args.len() > 1 { &args[1..] } else { &[] };
    match rest.first().map(String::as_str) {
        Some("serve") => cmd_serve(),
        Some("cli") => cmd_cli(&rest[1..]),
        Some(other) => {
            eprintln!("unknown command '{other}'");
            usage(&program);
            ExitCode::FAILURE
        }
        None => {
            usage(&program);
            ExitCode::FAILURE
        }
    }
}
