# REST API

Base URL: `http://<host>:51821`. All API routes live under `/api`, plus public
`GET /cnf/{token}` and `GET /metrics/*`. UI pages (`/`, `/clients/{id}`, `/me`,
`/login`, `/admin`, `/setup/*`) are HTML, not part of the API.

Source of truth: `src/web/router/routes.rs` + `src/web/handlers/*`. The handlers
are thin; logic lives in `src/web/backend/*` behind the `Backend` trait.

Every endpoint below has a `curl` example. All of them use the API token as
`$TOKEN` (and `$ADMIN_TOKEN` for ADMIN-only routes):

```bash
API=http://localhost:51821
TOKEN=...      # clear value returned once by POST /api/me/tokens
ADMIN_TOKEN=... # token of an ADMIN account
AUTH=(-H "Authorization: Bearer $TOKEN")
AUTH_ADMIN=(-H "Authorization: Bearer $ADMIN_TOKEN")
JSON=(-H 'Content-Type: application/json')
```

## Conventions

| Topic | Rule |
| --- | --- |
| Body | JSON **or** urlencoded (`JsonOrForm`). Client/admin patches also accept form. |
| Content | `Content-Type: application/json` for JSON. Max body 1 MiB (`413` over). |
| Paths | Strict: trailing slash is `404` on `/api`, `/metrics`, `/cnf`. Only `//` doubling `308`-redirects. |
| Errors | `{ "error": "<short message>" }`. `500` is always `{ "error": "internal error" }`. |
| Cache | Dynamic responses are `Cache-Control: no-store`. |
| CSRF | Mutating `POST\|PUT\|PATCH\|DELETE` with `Sec-Fetch-Site: cross-site` (or `same-site`) is `403`. Header absent (curl, Bearer API) is allowed. |

## Auth

**`Authorization: Bearer <api-token>` is the API credential** (`src/web/guards.rs`).
No password and no browser credential authenticates an API call: long-lived
tokens are the only thing you put on `/api/*`.

- Tokens are created under `POST /api/me/tokens` and shown **exactly once**
  (only their SHA-256 hex is stored, never the clear value).
- Bearer stays valid on 2FA accounts: it is an explicit, revocable credential
  (list/revoke under `/api/me/tokens`, or `/api/admin/tokens` as ADMIN), not a
  password bypass.
- Unknown/revoked/expired/disabled tokens answer `401` (no oracle).
- The scheme is case-insensitive (`Bearer`, `bearer`, …).

Unauthenticated → `401`. Authenticated but insufficient role → `403`
(`ADMIN` has everything; `CLIENT` is scoped to its own clients/profile).
Unknown permission strings are `500` by design.

The `/api/auth/*` routes below serve only the browser login/2FA flow; they do
**not** produce an API credential — issue a token from `/api/me/tokens` instead.

Rate limits (in-memory, per IP unless noted): login 10/min per `(IP, username)`
+ 50/min per IP, `verify-2fa` per-IP, Bearer credential failures 10/min/IP
(shared bucket, successes never count), client/admin mutations per-IP,
`/cnf` 20/min/IP, `/metrics` failures 30/min/IP, `/setup` 20/min/IP.

## Public

### `GET /api/information`

No auth. Version, setup state, feature flags (`release` is always `null` —
no in-process TLS client, kept for v15 shape parity).

```json
{ "version": "0.2.0", "setup": false, "setupStep": 0, "insecure": true,
  "metricsPrometheus": false, "oauthEnabled": false, "release": null }
```

```bash
curl "${AUTH[@]}" -X GET "$API/api/information"
```

## Web UI auth (not API authentication)

Browser login/2FA only — these routes never mint an API credential.

### `GET /api/auth/methods`

No auth. `{ "passwordDisabled": false, "oauthEnabled": false }`.

```bash
curl -X GET "$API/api/auth/methods"
```

### `POST /api/auth/password`

Body `{ "username": "...", "password": "..." }`. Success → `200 { "ok": true }`.
2FA account → `200 { "totpRequired": true, "pending": "<22-char id>" }`. htmx
callers get `HX-Redirect: /` or `/login/2fa`.

```bash
curl -X POST "$API/api/auth/password" "${JSON[@]}" \
  -d '{"username":"admin","password":"change-me-to-12-chars-min"}'
```

### `GET /api/auth/pending`

Checks the pending 2FA id (`X-Pending` header) is still valid.
→ `{ "pending": true|false }`.

```bash
curl -X GET "$API/api/auth/pending" -H 'X-Pending: <22-char id>'
```

### `POST /api/auth/verify-2fa`

Body `{ "code": "123456", "pending": "<id>" }` (`id` alias accepted; empty
falls back to the `X-Pending` header). Wrong code is retryable; 5 wrong codes
invalidate the pending; valid code is single-use. Success → `{ "ok": true }`.

```bash
curl -X POST "$API/api/auth/verify-2fa" "${JSON[@]}" \
  -d '{"code":"123456","pending":"<22-char id>"}'
```

### `POST /api/auth/cancel`

Drops the pending id. → `{ "ok": true }`.

```bash
curl -X POST "$API/api/auth/cancel" "${JSON[@]}" -H 'X-Pending: <22-char id>' -d '{}'
```

## Session / profile

Auth required (`Authorization: Bearer <api-token>`).

| Method + path | Description |
| --- | --- |
| `GET /api/session` | Own `UserView` (`id, username, name, role, totpEnabled, totpVerified`). |
| `DELETE /api/session` | Web UI logout (revokes the browser credential). → `{ "ok": true }`. |
| `POST /api/me` | Update display name. Body `{ "name": "..." }` (1–128 chars). |
| `POST /api/me/username` | Change login. Body `{ "currentPassword": "...", "username": "..." }`. |
| `POST /api/me/password` | Change password. Body `{ "currentPassword": "...", "newPassword": "..." }` (12+ chars). Revokes every API token of the account (and its web sessions). |
| `POST /api/me/totp` | Body `{ "action": "start\|confirm\|remove", "code"?, "password"? }`. `start` needs current `password` (even for first enrollment) → `{ "secret", "otpauth_url", "qr_svg" }` (JSON API; htmx gets an HTML fragment). `confirm` needs 6-digit `code` + current `password`. `remove` needs current `password`. |
| `GET /api/me/tokens` | Own API tokens (`id, userId, name, expiresAt?, lastUsedAt?, createdAt, enabled`). Never the clear value nor the hash. |
| `POST /api/me/tokens` | Create. Body `{ "name": "…" (1–64 chars), "expiresAt"?: "ISO-8601" or "DD-MM-YYYY" \| null }` (absent/empty/`null` = permanent, past = `400`). → `{ "id", "name", "token", "expiresAt"?, "createdAt" }`: `token` is the clear value, returned **exactly once** (htmx callers get `{"ok":true}` + `HX-Trigger {"refreshMe","showToken"}`: the value opens once in the modal). |
| `DELETE /api/me/tokens/{id}` | Revoke own token. Unknown id and another user's id both answer `404` (anti-enumeration). → `{ "ok": true }`. |

```bash
# GET /api/session
curl "${AUTH[@]}" -X GET "$API/api/session"

# DELETE /api/session
curl "${AUTH[@]}" -X DELETE "$API/api/session"

# POST /api/me
curl "${AUTH[@]}" -X POST "$API/api/me" "${JSON[@]}" -d '{"name":"CI bot"}'

# POST /api/me/username
curl "${AUTH[@]}" -X POST "$API/api/me/username" "${JSON[@]}" \
  -d '{"currentPassword":"change-me-to-12-chars-min","username":"ci"}'

# POST /api/me/password  (revokes every token of the account)
curl "${AUTH[@]}" -X POST "$API/api/me/password" "${JSON[@]}" \
  -d '{"currentPassword":"change-me-to-12-chars-min","newPassword":"another-12-chars-min"}'

# POST /api/me/totp — start / confirm / remove
curl "${AUTH[@]}" -X POST "$API/api/me/totp" "${JSON[@]}" \
  -d '{"action":"start","password":"change-me-to-12-chars-min"}'
curl "${AUTH[@]}" -X POST "$API/api/me/totp" "${JSON[@]}" \
  -d '{"action":"confirm","code":"123456","password":"change-me-to-12-chars-min"}'
curl "${AUTH[@]}" -X POST "$API/api/me/totp" "${JSON[@]}" \
  -d '{"action":"remove","password":"change-me-to-12-chars-min"}'

# GET /api/me/tokens
curl "${AUTH[@]}" -X GET "$API/api/me/tokens"

# POST /api/me/tokens  (clear value returned ONCE)
curl "${AUTH[@]}" -X POST "$API/api/me/tokens" "${JSON[@]}" \
  -d '{"name":"ci","expiresAt":"2027-01-01T00:00:00Z"}'

# DELETE /api/me/tokens/{id}
curl "${AUTH[@]}" -X DELETE "$API/api/me/tokens/1"
```

## Clients

Auth required. `CLIENT` role sees only its own rows; unknown/forbidden ids
answer `404` (anti-enumeration). `ADMIN` can do everything. Every
`POST|DELETE` runs a full `Tunnel::apply` **except** `generateOneTimeLink`.

`ClientView` (camelCase): `id, userId, name, enabled, hasPreSharedKey`
(key material never exposed), `ipv4Address, ipv6Address?, allowedIpsV4?,
allowedIpsV6?, serverAllowedIpsV4, serverAllowedIpsV6, firewallIpsV4?,
firewallIpsV6?, dnsV4?, dnsV6?, mtu, persistentKeepalive, serverEndpoint?,
expiresAt?` (ISO-8601 UTC, `null` = permanent), live fields `endpoint?,
latestHandshakeAt?, rxBytes, txBytes, connected`. `null` = inherit the global
default of the same family, never `[]`.

| Method + path | Permission | Description |
| --- | --- | --- |
| `GET /api/client?filter=&sort=` | `clients.custom` when filtered/sorted, else any auth | List. `filter` substring on name/IP/key, `sort` = `name\|-name\|created\|-created`. Returns `ClientView[]`. |
| `POST /api/client` | `clients.create` (ADMIN-only) | Create. Body `{ "name": "..." }` (1–64 chars). IP/keys auto-allocated. |
| `GET /api/client/{id}` | `clients.view` | One client. |
| `POST /api/client/{id}` | `clients.update` | Free-form patch: `name, allowedIpsV4/V6, firewallIpsV4/V6, dnsV4/V6` (arrays or CSV, `""` → `null` inherit), `mtu, persistentKeepalive` (numbers), `enabled` (bool), `expiresAt, serverEndpoint, preSharedKey` (nullable). `serverAllowedIpsV4/V6` + `expiresAt` are ADMIN-only (403 for CLIENT). Partial PATCH semantics: absent keys are left alone (JSON); urlencoded forms follow checkbox rules (absent = unchecked = `false`). |
| `DELETE /api/client/{id}` | `clients.delete` | Remove. → `{ "ok": true }`. |
| `POST /api/client/{id}/enable` | `clients.update` | Enable (422 if expired). |
| `POST /api/client/{id}/disable` | `clients.update` | Disable. |
| `POST /api/client/{id}/psk` | `clients.update` | Generate per-client PSK. |
| `DELETE /api/client/{id}/psk` | `clients.update` | Remove per-client PSK. |
| `POST /api/client/{id}/rotateKeys` | `clients.update` | New keypair (PSK kept). |
| `POST /api/client/{id}/generateOneTimeLink` | `clients.update` | New OTL `{ "token", "expires_at", "url" }`. No kernel effect. |
| `GET /api/client/{id}/configuration` | `clients.view` | `.conf` file download (`Content-Disposition: attachment`, filename ≤ 32 chars). |
| `GET /api/client/{id}/qrcode.svg` | `clients.view` | QR of the `.conf` as `image/svg+xml`. |

```bash
# GET /api/client  (+ ?filter= & ?sort=)
curl "${AUTH[@]}" -X GET "$API/api/client"
curl "${AUTH[@]}" -X GET "$API/api/client?filter=phone&sort=-created"

# POST /api/client (ADMIN)
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/client" "${JSON[@]}" -d '{"name":"phone"}'

# GET /api/client/{id}
curl "${AUTH[@]}" -X GET "$API/api/client/1"

# POST /api/client/{id} (patch)
curl "${AUTH[@]}" -X POST "$API/api/client/1" "${JSON[@]}" \
  -d '{"mtu":1420,"dnsV4":null,"allowedIpsV4":["10.8.0.2/32"]}'
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/client/1" "${JSON[@]}" \
  -d '{"serverAllowedIpsV4":["0.0.0.0/0"],"expiresAt":"2027-01-01T00:00:00Z"}'

# DELETE /api/client/{id}
curl "${AUTH[@]}" -X DELETE "$API/api/client/1"

# POST /api/client/{id}/enable
curl "${AUTH[@]}" -X POST "$API/api/client/1/enable" -d ''

# POST /api/client/{id}/disable
curl "${AUTH[@]}" -X POST "$API/api/client/1/disable" -d ''

# POST /api/client/{id}/psk
curl "${AUTH[@]}" -X POST "$API/api/client/1/psk" -d ''

# DELETE /api/client/{id}/psk
curl "${AUTH[@]}" -X DELETE "$API/api/client/1/psk"

# POST /api/client/{id}/rotateKeys
curl "${AUTH[@]}" -X POST "$API/api/client/1/rotateKeys" -d ''

# POST /api/client/{id}/generateOneTimeLink
curl "${AUTH[@]}" -X POST "$API/api/client/1/generateOneTimeLink" -d ''

# GET /api/client/{id}/configuration
curl "${AUTH[@]}" -X GET "$API/api/client/1/configuration" -o phone.conf

# GET /api/client/{id}/qrcode.svg
curl "${AUTH[@]}" -X GET "$API/api/client/1/qrcode.svg" -o phone.svg
```

## Admin (`admin.any`, ADMIN-only)

`GET` returns the object, `POST` takes a free-form patch (same `""` → `null`
coercion) and re-applies the tunnel: hot `wg syncconf`, or full `down`+`up`
(brief cut) when a non-hot key changed (MTU, `routingTable`, CIDR, hooks).

| Method + path | Description |
| --- | --- |
| `GET\|POST /api/admin/general` | `{ "sessionTimeout", "metricsPrometheus", "metricsJson", "metricsPasswordSet" }`. Never exposes the metrics hash. `POST` also accepts write-only `metricsPassword`: absent/empty keeps the stored hash, explicit `null` clears it, non-empty string sets a new one (≤ 1024 chars). Enabling either metrics flag without a stored password is `400 metricsPassword required`. |
| `GET\|POST /api/admin/hooks` | `{ "preUp", "postUp", "preDown", "postDown" }`. Any change → restart. |
| `GET\|POST /api/admin/interface` | `{ "name, device, port, publicKey, ipv4Cidr, ipv6Cidr, mtu, routingTable, firewallEnabled }`. `mtu`/`routingTable` change → restart. |
| `GET\|POST /api/admin/userconfig` | `{ "host, port, defaultDnsV4/V6, defaultAllowedIpsV4/V6, defaultMtu, defaultKeepalive, defaultPreSharedKey }`. Hot apply. |
| `POST /api/admin/interface/cidr` | Reallocate pools. Body `{ "ipv4Cidr"?, "ipv6Cidr"? }`. CIDR change → restart (+ NAT hooks rewrite). |
| `POST /api/admin/interface/restart` | Explicit `wg-quick down`+`up`. Cuts tunnels. → `{ "ok": true }`. |
| `GET /api/admin/ip-info` | Public-IP/hostname candidates (15-min cache). |
| `GET /api/admin/tokens` | Every API token (same shape as `GET /api/me/tokens`). |
| `DELETE /api/admin/tokens/{id}` | Revoke any API token. → `{ "ok": true }`. |

```bash
# GET /api/admin/general
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/general"

# POST /api/admin/general
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/general" "${JSON[@]}" \
  -d '{"metricsPrometheus":true,"metricsPassword":"<metrics-password>"}'

# GET /api/admin/hooks
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/hooks"

# POST /api/admin/hooks  (restart)
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/hooks" "${JSON[@]}" \
  -d '{"postUp":"iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE","postDown":"-"}'

# GET /api/admin/interface
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/interface"

# POST /api/admin/interface
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/interface" "${JSON[@]}" \
  -d '{"port":51821,"mtu":1420}'

# GET /api/admin/userconfig
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/userconfig"

# POST /api/admin/userconfig  (hot apply)
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/userconfig" "${JSON[@]}" \
  -d '{"host":"wg.example.org","defaultMtu":1420,"defaultKeepalive":25}'

# POST /api/admin/interface/cidr  (restart + NAT rewrite)
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/interface/cidr" "${JSON[@]}" \
  -d '{"ipv4Cidr":"10.9.0.0/24"}'

# POST /api/admin/interface/restart
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/admin/interface/restart" -d ''

# GET /api/admin/ip-info
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/ip-info"

# GET /api/admin/tokens
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/admin/tokens"

# DELETE /api/admin/tokens/{id}
curl "${AUTH_ADMIN[@]}" -X DELETE "$API/api/admin/tokens/1"
```

## API tokens

Long-lived `Bearer` credentials — the **only** way to call `/api/*` — managed
per account (plus a `/me` section in the UI: list + create form + revoke
buttons, all htmx, no inline JS). See the session/profile examples above.

Bootstrap: for the very first token there is no token yet — mint the admin
through the setup wizard (`POST /api/setup/2`) or the CLI
(`wg-ez cli db:admin:reset`), then create a token from the UI `/me` page.

Rules: only the SHA-256 hex is stored (see `src/store/api_token.rs`;
generation/validation in `src/web/backend/api_tokens.rs`, guard in
`src/web/guards.rs`); `expiresAt` absent/`null` = permanent; expired tokens
are auto-disabled by the 60 s cron (DB-only, no `Tunnel::apply`); failed
Bearer checks share the 10/min/IP credential bucket; the clear value is never
logged.

**Rotation revokes tokens.** `POST /api/me/password` (and the CLI
`db:admin:reset`) deletes every API token of the account, so a token leaked
before the change stops working immediately — re-issue one after rotating.
Disabling the account and deleting it have the same effect (`enabled=0` fails
every token check; the row cascades on `DELETE`). Rescue CLI: `wg-ez cli
api-tokens:list [--user <name>]` / `wg-ez cli api-tokens:revoke <id>` (see
`docs/setup.md`).

## Setup wizard (only during setup)

- `POST /api/setup/2` (public, only at `setupStep == 1`): `{ "username",
  "password" }` (12+ chars) → creates admin, advances to step 3.
- `GET /api/setup/3` (admin, only at step 3): suggested host/port.
- `POST /api/setup/3` (admin, only at step 3): `{ "host", "port" }` →
  finishes (`setupStep = 0`).

```bash
# POST /api/setup/2  (public)
curl -X POST "$API/api/setup/2" "${JSON[@]}" \
  -d '{"username":"admin","password":"change-me-to-12-chars-min"}'

# GET /api/setup/3
curl "${AUTH_ADMIN[@]}" -X GET "$API/api/setup/3"

# POST /api/setup/3
curl "${AUTH_ADMIN[@]}" -X POST "$API/api/setup/3" "${JSON[@]}" \
  -d '{"host":"wg.example.org","port":51821}'
```

## Metrics

Fail-closed (live-verified): a Bearer token is **always** required —
`Authorization: Bearer <metricsPassword>`. Note this Bearer credential is the
**metrics password, not an API token**: `/metrics/*` does not accept the tokens
from `/api/me/tokens` (separate store, separate check). With no stored
password every request is `401 metrics auth required`, even with both flags
off. Set the password via `POST /api/admin/general` (`metricsPassword` field),
then enable `metricsPrometheus` / `metricsJson`. Order: Bearer check first
(`401`), then the per-endpoint flag (`400 metrics disabled` when off). Only
failed Bearer checks count toward the 30/min/IP limit (Argon2 is paid only
after the 429 pre-check).

- `GET /metrics/prometheus` → `text/plain; version=0.0.4` (`wireguard_*`
  gauges/counters, labels
  `interface,enabled,ipv4Address,ipv6Address,name` + `endpoint`).
- `GET /metrics/json` → `{ "wireguard_configured_peers",
  "wireguard_enabled_peers", "wireguard_connected_peers", "clients": [...] }`
  (`transfer_rx/tx`, `latest_handshake_at`, `endpoint`, `publicKey`).

```bash
# GET /metrics/prometheus
curl -H "Authorization: Bearer <metrics-password>" "$API/metrics/prometheus"

# GET /metrics/json
curl -H "Authorization: Bearer <metrics-password>" "$API/metrics/json"
```

## One-time links / live status

- `GET /cnf/{token}` (public): OTL download. Unknown → `404`, expired →
  `410`. Success extends expiry 10 s (anti-double-request grace: an immediate
  retry still returns `200`) then purges; served as `.conf` attachment.
  20/min/IP. The `url` field from `generateOneTimeLink` is a relative path
  (`/cnf/<token>`), prepend your public origin.
- `GET /api/status/stream` (auth, long-poll ≤ 25 s): body = connected-peer
  count (`text/html`), `HX-Trigger: {"refreshGridLive":true,"pollAgain":true}`
  on change, `{"pollAgain":true}` on timeout. Over global/per-IP parked cap →
  `429`.

```bash
# GET /cnf/{token}  (public)
curl -X GET "$API/cnf/<otl-token>" -o one-time.conf

# GET /api/status/stream
curl "${AUTH[@]}" -X GET "$API/api/status/stream"
```