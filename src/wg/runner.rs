//! Point d'injection pour tout accès système (`wg`, `wg-quick`, iptables).
//!
//! - [`SystemRunner`] : vraies commandes, seul runner autorisé en production.
//! - [`MockRunner`] / [`SharedRunner`] : doubles de test sans privilège.
//! - [`NoopRunner`] : ne fait rien (environnements sans noyau).
//!
//! Le binaire WireGuard est choisi par `WG_EXECUTABLE`, défaut `wg`.
//! Hors Linux, [`SystemRunner`] est un stub qui refuse toute exécution.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Binaire WireGuard retenu quand `WG_EXECUTABLE` est absent ou blanc.
const DEFAULT_WG_EXECUTABLE: &str = "wg";

/// Binaire WireGuard à invoquer (`WG_EXECUTABLE`, défaut `wg`).
///
/// Une valeur vide ou blanche retombe sur le défaut.
pub fn wg_executable() -> String {
    resolve_wg_executable(std::env::var("WG_EXECUTABLE").ok())
}

/// Pure resolver (testable sans toucher l'env, `set_var` étant `unsafe` en édition 2024).
pub fn resolve_wg_executable(var: Option<String>) -> String {
    var.filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WG_EXECUTABLE.to_owned())
}

/// Sortie d'une commande exécutée via un [`Runner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Code de sortie du processus.
    pub code: i32,
    /// Octets écrits sur stdout.
    pub stdout: Vec<u8>,
    /// Octets écrits sur stderr.
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    /// Sortie vide avec code 0.
    pub fn success() -> Self {
        Self {
            code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    /// Sortie texte avec code 0.
    pub fn stdout_text(text: &str) -> Self {
        Self {
            code: 0,
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    /// Vrai si le code de sortie vaut 0.
    pub fn is_success(&self) -> bool {
        self.code == 0
    }
}

/// Erreur d'exécution d'une commande système.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerError {
    /// Le processus n'a pas pu démarrer.
    Spawn(String),
    /// Le processus a terminé avec un code non nul.
    Failed {
        program: String,
        code: i32,
        stderr: String,
    },
    /// Plateforme sans support (stub hors Linux).
    Unsupported(&'static str),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(msg) => write!(f, "cannot spawn command: {msg}"),
            Self::Failed {
                program,
                code,
                stderr,
            } => {
                write!(f, "command `{program}` exited with {code}: {stderr}")
            }
            Self::Unsupported(msg) => write!(f, "unsupported platform: {msg}"),
        }
    }
}

impl std::error::Error for RunnerError {}

/// Exécuteur de commandes système (point d'injection pour les tests).
///
/// L'implémentation est synchrone : les appelants async doivent passer par
/// `spawn_blocking`. Un code de sortie non nul devient [`RunnerError::Failed`].
pub trait Runner: Send + Sync + fmt::Debug {
    /// Exécute `program` avec `args`, optionnellement en lui écrivant `stdin`.
    fn exec(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError>;

    /// Variante ergonomique avec des `&str` et sans stdin.
    fn exec_str(&self, program: &str, args: &[&str]) -> Result<CommandOutput, RunnerError> {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        self.exec(program, &owned, None)
    }
}

/// Exécute les vraies commandes du système.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

/// Vide un pipe d'enfant jusqu'à EOF sur un thread dédié.
///
/// La lecture doit être concurrente de l'attente de fin : sinon un enfant qui
/// remplit le tampon d'un pipe se bloquerait indéfiniment pendant qu'on sonde
/// son code de sortie (interblocage classique).
#[cfg(target_os = "linux")]
fn drain_pipe<R>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
        }
        buf
    })
}

#[cfg(target_os = "linux")]
impl Runner for SystemRunner {
    fn exec(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError> {
        use std::io::Write as _;
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        // A hung `wg`/`wg-quick`/`iptables` must never block a `spawn_blocking`
        // worker forever (the runtime is single-threaded with a finite pool).
        const TIMEOUT: Duration = Duration::from_secs(30);

        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| RunnerError::Spawn(format!("{program}: {e}")))?;

        if let Some(input) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| RunnerError::Spawn(format!("{program}: stdin unavailable")))?;
            pipe.write_all(input)
                .map_err(|e| RunnerError::Spawn(format!("{program}: {e}")))?;
            drop(pipe);
        }

        // Drain stdout/stderr from dedicated threads **before** waiting: if
        // the child fills a pipe buffer it would otherwise block forever while
        // we poll for exit (classic pipe deadlock).
        let out_handle = drain_pipe(child.stdout.take());
        let err_handle = drain_pipe(child.stderr.take());

        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = out_handle.join();
                        let _ = err_handle.join();
                        return Err(RunnerError::Spawn(format!(
                            "{program}: timed out after {}s",
                            TIMEOUT.as_secs()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return Err(RunnerError::Spawn(format!("{program}: {e}")));
                }
            }
        };

        let stdout = out_handle.join().unwrap_or_default();
        let stderr = err_handle.join().unwrap_or_default();
        let code = status.code().unwrap_or(-1);
        if status.success() {
            Ok(CommandOutput {
                code,
                stdout,
                stderr,
            })
        } else {
            Err(RunnerError::Failed {
                program: program.to_string(),
                code,
                stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
            })
        }
    }
}

/// Stub hors Linux : aucune exécution réelle n'est possible.
#[cfg(not(target_os = "linux"))]
impl Runner for SystemRunner {
    fn exec(
        &self,
        _program: &str,
        _args: &[String],
        _stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError> {
        Err(RunnerError::Unsupported(
            "SystemRunner requires Linux (wg/iptables)",
        ))
    }
}

/// Appel enregistré par [`MockRunner`], dans l'ordre d'arrivée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    /// Programme invoqué.
    pub program: String,
    /// Arguments transmis, dans l'ordre.
    pub args: Vec<String>,
    /// Contenu écrit sur stdin, `None` si le pipe n'a pas été ouvert.
    pub stdin: Option<Vec<u8>>,
}

impl RecordedCall {
    /// Forme canonique `programme arg1 arg2 ...` (utile pour les assertions).
    pub fn full_command(&self) -> String {
        full_command(&self.program, &self.args)
    }
}

fn full_command(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

/// État interne du [`MockRunner`], protégé par un unique mutex.
///
/// Un seul verrou garantit qu'un appel enregistré et la réponse qu'il
/// déclenche sont observés de façon cohérente, même entre tests parallèles.
#[derive(Debug, Default)]
struct MockState {
    calls: Vec<RecordedCall>,
    exact: HashMap<String, CommandOutput>,
    by_program: HashMap<String, CommandOutput>,
    default_fail: bool,
}

/// Double de test : enregistre les appels et rejoue des sorties programmées.
///
/// Résolution d'une sortie, dans l'ordre :
/// 1. commande exacte (`programme + args`) via [`MockRunner::respond`] ;
/// 2. programme seul via [`MockRunner::respond_program`] ;
/// 3. succès vide par défaut (sauf [`MockRunner::set_default_fail`] activé).
#[derive(Debug, Default)]
pub struct MockRunner {
    state: Mutex<MockState>,
}

impl MockRunner {
    /// Nouveau mock vide (succès vide par défaut).
    pub fn new() -> Self {
        Self::default()
    }

    /// Verrouille l'état interne en récupérant le contenu même si un test
    /// antérieur a paniqué en le détenant : un empoisonnement ne doit pas
    /// faire échouer les tests suivants.
    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Programme la sortie d'une commande exacte.
    pub fn respond(&self, program: &str, args: &[&str], output: CommandOutput) {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let key = full_command(program, &owned);
        self.lock().exact.insert(key, output);
    }

    /// Programme la sortie de tout appel à `program` (fallback).
    pub fn respond_program(&self, program: &str, output: CommandOutput) {
        self.lock().by_program.insert(program.to_string(), output);
    }

    /// Fait échouer par défaut les appels sans réponse programmée.
    pub fn set_default_fail(&self, fail: bool) {
        self.lock().default_fail = fail;
    }

    /// Appels enregistrés, dans l'ordre.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.lock().calls.clone()
    }

    /// Nombre d'appels enregistrés.
    pub fn call_count(&self) -> usize {
        self.lock().calls.len()
    }

    /// Appels filtrés sur un programme donné.
    pub fn calls_to(&self, program: &str) -> Vec<RecordedCall> {
        self.lock()
            .calls
            .iter()
            .filter(|c| c.program == program)
            .cloned()
            .collect()
    }

    fn finish(program: &str, out: &CommandOutput) -> Result<CommandOutput, RunnerError> {
        if out.is_success() {
            Ok(out.clone())
        } else {
            Err(RunnerError::Failed {
                program: program.to_string(),
                code: out.code,
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            })
        }
    }
}

impl Runner for MockRunner {
    fn exec(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError> {
        let key = full_command(program, args);
        let mut state = self.lock();
        state.calls.push(RecordedCall {
            program: program.to_string(),
            args: args.to_vec(),
            stdin: stdin.map(|s| s.to_vec()),
        });
        if let Some(out) = state.exact.get(&key) {
            return Self::finish(program, out);
        }
        if let Some(out) = state.by_program.get(program) {
            return Self::finish(program, out);
        }
        if state.default_fail {
            Err(RunnerError::Failed {
                program: program.to_string(),
                code: 1,
                stderr: "mock: no response programmed".to_string(),
            })
        } else {
            Ok(CommandOutput::success())
        }
    }
}

/// [`MockRunner`] partageable entre tests parallèles (`Arc` + `Clone`).
#[derive(Debug, Clone, Default)]
pub struct SharedRunner(pub Arc<MockRunner>);

impl SharedRunner {
    /// Nouveau mock partagé.
    pub fn new() -> Self {
        Self(Arc::new(MockRunner::new()))
    }

    /// Accès au mock sous-jacent (assertions).
    pub fn inner(&self) -> &MockRunner {
        &self.0
    }
}

impl Runner for SharedRunner {
    fn exec(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError> {
        self.0.exec(program, args, stdin)
    }
}

/// Runner inerte pour les environnements sans noyau : tout réussit.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRunner;

impl Runner for NoopRunner {
    fn exec(
        &self,
        _program: &str,
        _args: &[String],
        _stdin: Option<&[u8]>,
    ) -> Result<CommandOutput, RunnerError> {
        Ok(CommandOutput::success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_executable_defaults_to_wg() {
        assert_eq!(resolve_wg_executable(None), "wg");
    }

    #[test]
    fn wg_executable_blank_falls_back() {
        assert_eq!(resolve_wg_executable(Some("   ".to_string())), "wg");
        assert_eq!(
            resolve_wg_executable(Some("wg-test-bin".to_string())),
            "wg-test-bin"
        );
    }

    #[test]
    fn mock_records_and_replays_exact_first() {
        let mock = MockRunner::new();
        mock.respond("wg", &["genkey"], CommandOutput::stdout_text("PRIVKEY\n"));
        mock.respond_program("wg", CommandOutput::stdout_text("FALLBACK\n"));

        let out = mock
            .exec_str("wg", &["genkey"])
            .expect("mock exec should succeed");
        assert_eq!(
            String::from_utf8(out.stdout).expect("utf8").trim(),
            "PRIVKEY"
        );

        let out = mock
            .exec_str("wg", &["genpsk"])
            .expect("mock exec should succeed");
        assert_eq!(
            String::from_utf8(out.stdout).expect("utf8").trim(),
            "FALLBACK"
        );

        assert_eq!(mock.call_count(), 2);
        assert_eq!(mock.calls_to("wg").len(), 2);
        assert_eq!(mock.calls()[0].full_command(), "wg genkey".to_string());
    }

    #[test]
    fn mock_failure_output_becomes_failed_error() {
        let mock = MockRunner::new();
        mock.respond(
            "iptables",
            &["--bad"],
            CommandOutput {
                code: 2,
                stdout: Vec::new(),
                stderr: b"bad".to_vec(),
            },
        );
        let err = mock.exec_str("iptables", &["--bad"]).unwrap_err();
        assert!(matches!(err, RunnerError::Failed { code: 2, .. }));
    }

    #[test]
    fn shared_runner_delegates() {
        let shared = SharedRunner::new();
        let clone = shared.clone();
        clone.exec_str("wg", &["show"]).expect("noop success");
        assert_eq!(shared.inner().call_count(), 1);
    }

    #[test]
    fn noop_runner_always_succeeds() {
        let out = NoopRunner
            .exec_str("wg-quick", &["up", "wg0"])
            .expect("noop");
        assert!(out.is_success());
    }
}
