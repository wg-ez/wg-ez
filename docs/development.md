# Development

Requirements: Docker + Compose only. Everything compiles, lints and tests inside `docker/Dockerfile` stages — nothing is written to the source tree.

Build files live in `docker/` (`Dockerfile`, `compose.yml`, `compose.dev.yml`, `package.json`/`package-lock.json`); run every command from the repo root.

`docker/compose.dev.yml` is standalone: `up --build` runs the gates (fmt, clippy, tests, htmx) first, then builds and starts the server.

```bash
# Full dev build + gates + run:
docker compose -f docker/compose.dev.yml up --build
# Dev loop: sync static/, rebuild on src|templates|locales change:
docker compose -f docker/compose.dev.yml up --build --watch
# Logs / stop:
docker compose -f docker/compose.dev.yml logs -f
docker compose -f docker/compose.dev.yml down
```

Individual gates (warnings are errors):

```bash
docker build -f docker/Dockerfile --target fmt --progress=plain -t wg-ez-fmt .
docker build -f docker/Dockerfile --target clippy --progress=plain -t wg-ez-clippy .
docker build -f docker/Dockerfile --target test --progress=plain -t wg-ez-test .
# Single test subset:
docker build -f docker/Dockerfile --target test --progress=plain --build-arg TEST_FILTER=<substring> -t wg-ez-test .
# Via compose (uses the cache):
docker compose -f docker/compose.dev.yml up --build fmt
docker compose -f docker/compose.dev.yml up --build clippy
TEST_FILTER=<substring> docker compose -f docker/compose.dev.yml up --build test
docker compose -f docker/compose.dev.yml up --build htmx
```

CSS (verified inside the image, never written to the host):

```bash
docker build -f docker/Dockerfile --target css --progress=plain -t wg-ez-css .
```

HTTP audit — 270 checks against the dev server (start it first):

```bash
docker compose -f docker/compose.dev.yml --profile audit up --build audit
```

Local release image + cleanup:

```bash
docker build -f docker/Dockerfile -t wg-ez:latest .
docker compose -f docker/compose.dev.yml down -v
```

Layout: `src/tunnel/` is the only module touching the kernel (`wg syncconf`, firewall); `src/web/backend/*` holds the logic behind thin handlers; config is frozen at boot (`src/config/`); SQLite migrations are numbered files in `src/migrations/`. See `AGENTS.md` for the full contributor rules.
