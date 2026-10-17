# Setup & rescue

All settings are environment variables, read once at boot. No `environment:` block needed to run.

## Optional setup

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
| `HOST` | `0.0.0.0` | Bind address inside the container. |
| `PORT` | `51821` | Listen port inside the container (right side of the ports mapping). |
| host port mapping | `51821` | Left side of `"51821:51821/tcp"`; change it to remap the UI port. |
| `INSECURE` | `false` | `true` for plain HTTP (LAN without reverse proxy). Otherwise the `Secure` cookie is refused and login loops back to `/login`. Keep `false` behind HTTPS. |
| `IP_MODE` | `auto` | `auto` (detect from container routes) \| `ipv4` \| `ipv6` \| `both`. |
| `WG_INTERFACE` | `wg0` | WireGuard interface name. |
| `TRUSTED_PROXIES` | — | CSV of IPs/CIDRs allowed to set `X-Forwarded-For`. |
| `DISABLE_PASSWORD_AUTH` | `false` | Disable password login (SSO / hardware-key setups). |
| `INIT_ENABLED` | `false` | `true` = create the admin at first boot, no web wizard. |
| `INIT_USERNAME` / `INIT_PASSWORD` | — | Admin credentials (12+ chars). Required with `INIT_ENABLED`. |
| `INIT_HOST` / `INIT_PORT` | — | Public endpoint baked into client configs. Required with `INIT_ENABLED`. |
| `INIT_DNS` | `1.1.1.1` | Default client DNS (CSV of bare IPs). |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | Client pool. Server takes `.1`, clients `.2+`. |
| `INIT_IPV6_CIDR` | — | Empty = IPv6 disabled (e.g. `fd00::/64` to enable). |
| `INIT_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | Default client AllowedIPs. |

Legacy `PASSWORD` / `PASSWORD_HASH` (wg-easy v14 style) are refused at boot — create the admin via the wizard or `INIT_*`.

## Reverse proxy

Terminate TLS in front (Caddy, Traefik, nginx…). Keep `INSECURE=false`, forward to `51821/tcp`, and set `TRUSTED_PROXIES` to your proxy's IP/CIDR.

## Rescue CLI

Offline access, direct SQLite, never touches WireGuard:

```bash
docker exec -it wg-ez wg-ez cli db:admin:reset
docker exec -it wg-ez wg-ez cli clients:list
docker exec -it wg-ez wg-ez cli clients:qr <id>
docker exec -it wg-ez wg-ez cli api-tokens:list [--user <username>]
docker exec -it wg-ez wg-ez cli api-tokens:revoke <id>
```

Run `docker exec -it wg-ez wg-ez cli --help` for the full list.

`db:admin:reset` forces a new password on admin (id 1), clears its 2FA and
**revokes every session and every API token of that account** — the same
rotation semantics as `POST /api/me/password`. Any automation still using a
`Bearer` token must be re-issued afterwards (`api-tokens:list` to audit,
`api-tokens:revoke` to drop one by id).
