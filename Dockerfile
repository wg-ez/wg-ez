# syntax=docker/dockerfile:1.12
# wg-ez — Dockerfile, seul moyen de compiler.
# Multi-stage : CSS (Node) + portes qualite glibc (fmt/clippy/test) + Rust musl
# statique -> Alpine minimale, plus un stage `audit` (bash+curl). Toutes les
# cibles sont bâties SANS bind-mount de l'arbre source : le cache cargo vit dans
# un cache mount BuildKit, l'hôte ne recoit aucun artefact.
# Binaire ~4-5 Mo, sans Node au runtime ni au build Rust. Pas de pin : tags flottants.
#
# Chaine d'approvisionnement : les images de base (node:alpine, rust:bookworm,
# alpine:latest) restent des tags flottants (latest-only). Les dependances npm
# passent par `npm ci` sur le lockfile commite (versions resolues + hashes), et
# htmx est vendorise/verifie (service `htmx` du compose dev).
#
# Rapidite (surtout UI) : `static/` est servi depuis le FS au runtime
# (`static_file` lit `./static`), `templates/`+`locales/` sont compiles dans le
# binaire. Caches BuildKit + `develop.watch` du compose pour du CSS/JS instantane.

# ---------------------------------------------------------------- css ----
# Node tourne uniquement dans cette etape pour generer static/css/app.css via
# @tailwindcss/cli (seule dep npm). Cache en 2 couches : `npm ci` rejoue
# seulement si package.json/package-lock.json changent, tailwind seulement si
# input.css change. `npm ci` installe depuis le lockfile commite (versions
# resolues + hashes) ; les specs de package.json restent `latest`.
FROM node:alpine AS css
WORKDIR /work
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY static/css/input.css ./static/css/input.css
RUN ./node_modules/.bin/tailwindcss -i ./static/css/input.css -o ./static/css/app.css --minify

# ------------------------------------------------------------- devbase ----
# Socle des portes qualite (fmt/clippy/test) et du serveur de dev : toolchain
# glibc + sources + `app.css` frais du stage `css`. Aucun bind-mount : on
# compile/teste DANS l'image, le cache cargo vit dans un cache mount BuildKit
# (jamais dans l'arbre source). Le binaire musl de prod reste dans `builder`.
FROM rust:bookworm AS devbase
WORKDIR /work
# Cache cargo des cibles glibc, isole de celui du build musl (`/work/target`).
ENV CARGO_TARGET_DIR=/cargo-target
# Manifestes seuls d'abord : `cargo fetch` remplit registre/git sans etre
# invalide par une modif de source (meme logique que le builder).
COPY rust-toolchain.toml askama.toml Cargo.toml Cargo.lock build.rs ./
COPY .cargo/ ./.cargo/
COPY --from=css /work/static/css/app.css ./static/css/app.css
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo fetch --locked
COPY src/ ./src/
COPY templates/ ./templates/
COPY locales/ ./locales/
COPY static/ ./static/
COPY --from=css /work/static/css/app.css ./static/css/app.css
# Meme garde mtime que le builder : `COPY` conserve les mtimes hote, cargo
# (empreintes basees mtime) pourrait croire le crate a jour. Le `touch` rejoue
# exactement quand les `COPY` rejouent, jamais sinon.
RUN find src templates locales static build.rs Cargo.toml Cargo.lock askama.toml -exec touch {} +

# Porte fmt (`docker build --target fmt .`) : ne compile rien, n'ecrit rien.
FROM devbase AS fmt
RUN cargo fmt --check

# Porte clippy (`docker build --target clippy .`) : warnings = erreurs. CACHEBUST force le RUN a
# rejouer a chaque invocation (sinon BuildKit servirait le layer en cache) ; le
# cache `/cargo-target` conserve la compilation incrementale.
FROM devbase AS clippy
ARG CACHEBUST=0
RUN --mount=type=cache,target=/cargo-target,sharing=locked \
    echo "clippy cache-bust: $CACHEBUST" >/dev/null && \
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Porte tests (`docker build --target test .`) : tests unitaires sans privilege via MockRunner.
# `TEST_FILTER` restreint a un sous-ensemble (`cargo test <filtre>`), vide = tous.
FROM devbase AS test
ARG CACHEBUST=0
ARG TEST_FILTER=""
RUN --mount=type=cache,target=/cargo-target,sharing=locked \
    echo "test cache-bust: $CACHEBUST" >/dev/null && \
    cargo test --locked $TEST_FILTER

# Serveur de dev glibc (stage `dev`, `docker build --target dev .`) : binaire debug cuit dans l'image, `/work`
# comme CWD pour servir `static/`. `/etc/wireguard` fourni en tmpfs au run, donc
# aucune ecriture hote. `wireguard-tools` fournit `wg genkey` (sinon `serve`
# refuse de fabriquer une paire de cles) ; le boot kernel echoue proprement
# faute de NET_ADMIN et le serveur demarre quand meme.
FROM devbase AS dev
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends wireguard-tools
RUN --mount=type=cache,target=/cargo-target,sharing=locked \
    cargo build --locked && \
    cp /cargo-target/debug/wg-ez /usr/local/bin/wg-ez
CMD ["/usr/local/bin/wg-ez", "serve"]

# --------------------------------------------------------------- audit ----
# Outils du service `audit` du compose dev (270 checks HTTP) : bash + curl + python3 (JSON/TOTP)
# + scripts embarques. Lance en `--network host` contre le serveur publie par
# Compose.
FROM alpine:latest AS audit
RUN apk add --no-cache bash curl python3
COPY scripts/ /scripts/
WORKDIR /scripts
ENTRYPOINT ["bash", "/scripts/audit.sh"]

# ------------------------------------------------------------ builder ----
# Rust derniere stable, binaire musl 100 % statique (+crt-static via
# .cargo/config.toml). Cross depuis hote glibc vers musl. Cibles livrees :
# x86_64-unknown-linux-musl et aarch64-unknown-linux-musl (buildx).
FROM rust:bookworm AS builder
ARG TARGETARCH
WORKDIR /work
# Compilo C + cross musl pour l'amalgame SQLite (rusqlite `bundled`, seul C autorise).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends gcc musl-tools musl-dev make perl
RUN rustup component add rustfmt clippy llvm-tools-preview && \
    case "${TARGETARCH:-amd64}" in \
      amd64) TRIPLE=x86_64-unknown-linux-musl ;; \
      arm64) TRIPLE=aarch64-unknown-linux-musl ;; \
      *) echo "arch non supportee: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$TRIPLE" && \
    echo "$TRIPLE" > /tmp/musl_triple
# Manifestes seuls d'abord : `cargo fetch` remplit les caches registre/git hors
# du chemin critique de la compilo. Pas de pre-build avec sources factices :
# un binaire factice qui fuirait dans l'image sortirait en code 0 sans un mot.
COPY rust-toolchain.toml askama.toml Cargo.toml Cargo.lock build.rs ./
COPY .cargo/ ./.cargo/
COPY --from=css /work/static/css/app.css ./static/css/app.css
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo fetch
# Vrai code : seul ce layer est invalide par une modif src/templates/locales/static.
# Lint et tests via les stages glibc (`docker build --target fmt|clippy|test .`), pas ici.
COPY src/ ./src/
COPY templates/ ./templates/
COPY locales/ ./locales/
COPY static/ ./static/
COPY --from=css /work/static/css/app.css ./static/css/app.css
# `COPY` conserve les mtimes de l'hote : sans ca, cargo (empreintes basees
# mtime) croit le crate a jour des qu'une empreinte plus recente traine dans
# le cache `target/` et embarque un binaire perime sans recompiler. Le `touch`
# rejoue exactement quand les `COPY` rejouent (meme invalidation), jamais sinon.
RUN find src templates locales static build.rs Cargo.toml Cargo.lock askama.toml -exec touch {} +
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/work/target \
    cargo build --release --target "$(cat /tmp/musl_triple)" && \
    mkdir -p /out && \
    cp "target/$(cat /tmp/musl_triple)/release/wg-ez" /out/wg-ez && \
    ls -la /out/wg-ez && \
    /out/wg-ez bogus-command 2>&1 | grep -q "unknown command"
# Portes qualite (stages glibc `fmt`/`clippy`/`test`, `docker build --target <stage> .`)
# plus haut, jamais dans cette etape musl.

# ------------------------------------------------------------ runtime ----
# Alpine minimale : pas de toolchain, pas de Node. wireguard-tools +
# iptables-legacy, `wg-quick down` propre a l'arret.
FROM alpine:latest AS runtime
RUN apk add --no-cache \
      wireguard-tools \
      iptables \
      iptables-legacy \
      ip6tables \
      nftables \
      kmod \
      iproute2 \
      bash && \
    ln -sf /usr/sbin/iptables-legacy /usr/sbin/iptables && \
    ln -sf /usr/sbin/ip6tables-legacy /usr/sbin/ip6tables && \
    ln -sf /usr/sbin/iptables-legacy /usr/bin/iptables 2>/dev/null || true && \
    wg --version && iptables --version
COPY --from=builder /out/wg-ez /usr/local/bin/wg-ez
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Assets servis depuis le filesystem (handler `static_file` lit `static/...`
# relatif au CWD) : on les embarque dans l'image runtime.
COPY static/ /static/
COPY templates/ /templates/
COPY locales/ /locales/
# CSS frais du stage css par-dessus l'artefact commite (cf. builder).
COPY --from=css /work/static/css/app.css /static/css/app.css
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/wg-ez
WORKDIR /
# Migrations SQL embarquees dans le binaire via include_str! (build.rs) ;
# la DB et le .conf vivent dans /etc/wireguard (volume compose).
ENV HOST=0.0.0.0 \
    PORT=51821 \
    WG_INTERFACE=wg0 \
    WG_EXECUTABLE=wg
EXPOSE 51821/tcp
VOLUME ["/etc/wireguard"]
# Healthcheck : `wg show` doit exposer l'interface (timeout 5s, 1m, x3).
HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
  CMD wg show 2>/dev/null | grep -q interface || exit 1
STOPSIGNAL SIGTERM
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
