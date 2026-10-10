# wg-ez

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.99+-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?style=flat-square&logo=docker&logoColor=white)](https://ghcr.io/wg-ez/wg-ez)
[![WireGuard](https://img.shields.io/badge/WireGuard-VPN-red?style=flat-square&logo=wireguard&logoColor=white)](https://www.wireguard.com)

WireGuard server with a web UI and an offline rescue CLI, shipped as a single
static binary (~5 MB, no runtime dependencies). A Rust reimplementation of
wg-easy.

- Manage clients from a web UI (create, QR code, `.conf` download, enable/disable, one-time links)
- Single static musl binary + Alpine runtime image, SQLite embedded (no external DB)
- Hot-apply config changes via `wg syncconf`, firewall (iptables) rebuilt automatically
- IPv4 / IPv6 / dual-stack pools, 2FA (TOTP), per-client settings, metrics endpoint
- Offline CLI for rescue when the server is broken (`wg-ez cli ...`)

## Quick start

Requirements: Docker + Docker Compose.

```bash
docker compose up -d
```

Then open `http://<server-ip>:51821` and finish the setup wizard
(or pre-create the admin with `INIT_*`, see below).

Ports:

| Port | Protocol | Purpose |
| --- | --- | --- |
| 51821 | TCP | Web UI + API |
| 51820 | UDP | WireGuard traffic |

Data (SQLite DB + `wg0.conf`) lives in the `./wg-data` directory next to the
compose file, so recreating the container keeps your configuration.

```bash
docker compose logs -f   # follow logs
docker compose down      # clean stop (runs wg-quick down)
```

To update:

```bash
docker compose pull && docker compose up -d
```

Image: `ghcr.io/wg-ez/wg-ez:latest` (pin a release tag, e.g. `:v1.0.0`, in production).

## Configuration

All settings are environment variables, read once at boot, with sane defaults
— the compose file needs no `environment:` block to run. To override, add one
under the service:

```yaml
services:
  wg-ez:
    environment:
      INSECURE: "true"
      INIT_ENABLED: "true"
      INIT_USERNAME: admin
      INIT_PASSWORD: change-me-to-12-chars-min
      INIT_HOST: vpn.example.com
      INIT_PORT: "51820"
```

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Address the server binds to inside the container. |
| `PORT` | `51821` | Port the server listens on inside the container (right side of the ports mapping). |
| host port mapping | `51821` | Left side of `"51821:51821/tcp"`; change it to remap the UI port on the host. |
| `INSECURE` | `false` | Set `true` for plain-HTTP access (LAN without reverse proxy). Otherwise the `Secure` session cookie is refused and login loops back to `/login`. Keep `false` behind HTTPS. |
| `IP_MODE` | `auto` | Address families: `auto` (detect IPv6) \| `ipv4` \| `ipv6` \| `both`. |
| `WG_INTERFACE` | `wg0` | WireGuard interface name. |
| `TRUSTED_PROXIES` | — | CSV of IPs/CIDRs allowed to set `X-Forwarded-For` (reverse proxy). |
| `DISABLE_PASSWORD_AUTH` | `false` | Disable password login (SSO/hardware-key style setups). |
| `INIT_ENABLED` | `false` | `true` = create the admin at first boot without the web wizard. |
| `INIT_USERNAME` / `INIT_PASSWORD` | — | Admin credentials (password: 12+ chars). Required with `INIT_ENABLED`. |
| `INIT_HOST` / `INIT_PORT` | — | Public endpoint baked into client configs. Required with `INIT_ENABLED`. |
| `INIT_DNS` | `1.1.1.1` | Default client DNS (CSV of bare IPs). |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | Client pool. Server takes `.1`, clients `.2+`. |
| `INIT_IPV6_CIDR` | — | Empty = IPv6 disabled at setup (e.g. `fd00::/64` to enable). |
| `INIT_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | Default client AllowedIPs. |

Legacy `PASSWORD` / `PASSWORD_HASH` (wg-easy v14 style) are refused at boot
with a migration pointer — create the admin via the wizard or `INIT_*`.

### Reverse proxy

Run the container as-is and terminate TLS in front of it
(Caddy, Traefik, nginx…). Keep `INSECURE=false`, forward to the container's
`51821/tcp`, and set `TRUSTED_PROXIES` to your proxy's IP/CIDR so client IPs
are logged correctly.

## Rescue CLI

If the web server is unusable, run the offline CLI inside the container
(direct SQLite access, never touches WireGuard):

```bash
docker exec -it wg-ez wg-ez cli db:admin:reset
docker exec -it wg-ez wg-ez cli clients:list
docker exec -it wg-ez wg-ez cli clients:qr <id>
```

## Development

Requirements: Docker + Compose, nothing else. Everything compiles, lints
and tests inside Dockerfile stages — nothing is written to the source tree.

`docker-compose.dev.yml` is standalone (no second `-f` needed): `up --build`
runs the gates (fmt, clippy, tests, htmx hash check) first, then builds and
starts the server. `wg-ez` only starts if all gates succeed.

```bash
# Full dev build + gates + run:
docker compose -f docker-compose.dev.yml up --build
# Dev loop: sync static/, rebuild on src|templates|locales change:
docker compose -f docker-compose.dev.yml up --build --watch
# Follow logs / stop:
docker compose -f docker-compose.dev.yml logs -f
docker compose -f docker-compose.dev.yml down
```

Individual gates (same stages the dev compose runs, warnings are errors):

```bash
docker build --target fmt --progress=plain -t wg-ez-fmt .
docker build --target clippy --progress=plain -t wg-ez-clippy .
docker build --target test --progress=plain -t wg-ez-test .
# Single test subset:
docker build --target test --progress=plain --build-arg TEST_FILTER=<substring> -t wg-ez-test .
# Single gate via compose (uses the cache, no rebuild if sources unchanged):
docker compose -f docker-compose.dev.yml up --build fmt
docker compose -f docker-compose.dev.yml up --build clippy
TEST_FILTER=<substring> docker compose -f docker-compose.dev.yml up --build test
docker compose -f docker-compose.dev.yml up --build htmx
```

CSS + vendored JS (both verified inside images, never written to the host):

```bash
docker build --target css --progress=plain -t wg-ez-css .   # regenerate/validate static/css/app.css
```

HTTP audit — 270 checks against the dev server (start it first, other terminal):

```bash
docker compose -f docker-compose.dev.yml --profile audit up --build audit
```

Local release image + cleanup:

```bash
docker build -t wg-ez:latest .
docker compose -f docker-compose.dev.yml down -v
```

Layout: `src/tunnel/` is the only module touching the kernel
(`wg syncconf`, firewall); `src/web/backend/*` holds the logic behind thin
handlers; config is frozen at boot (`src/config/`); SQLite migrations are
numbered files in `src/migrations/`. See `AGENTS.md` for the full
contributor rules.

## License

MIT — see [LICENSE](LICENSE).
