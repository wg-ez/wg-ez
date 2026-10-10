<p align="center">
  <img src="static/img/favicon.svg" width="96" alt="wg-ez logo" />
</p>

<h1 align="center">wg-ez</h1>

<p align="center">
  WireGuard server + Web UI + offline CLI in one static binary.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT" /></a>
  <img src="https://img.shields.io/badge/rust-1.99+-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <a href="https://ghcr.io/wg-ez/wg-ez"><img src="https://img.shields.io/badge/docker-ghcr.io-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker" /></a>
  <img src="https://img.shields.io/badge/WireGuard-VPN-red?style=flat-square&logo=wireguard&logoColor=white" alt="WireGuard" />
</p>

<p align="center">
  <img src="screenshot.png" width="100%" alt="wg-ez clients page" />
</p>

## Quick start

```yaml
# docker-compose.yml
services:
  wg-ez:
    image: ghcr.io/wg-ez/wg-ez:latest
    container_name: wg-ez
    ports:
      - 51821:51821 # Web UI
      - 51820:51820/udp # WireGuard traffic
    volumes:
      - ./wg-data:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      net.ipv4.ip_forward: 1
      net.ipv6.conf.all.forwarding: 1
    restart: unless-stopped

networks:
  default:
    enable_ipv6: true
```

## Docs

- [Setup & rescue](docs/setup.md) — options, reverse proxy, password reset
- [Development](docs/development.md) — build, tests, audit

## License

MIT — see [LICENSE](LICENSE).
