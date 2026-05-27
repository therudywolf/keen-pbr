# 🐺 keen-pbr — Forest-PBR Edition

[![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0-22c55e.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Edition](https://img.shields.io/badge/edition-Forest--PBR-67f0ff)](#)
[![keen-pbr core](https://img.shields.io/badge/keen--pbr_core-3.0.3-6b7280)](https://github.com/maksimkurb/keen-pbr)

**keen-pbr — Forest-PBR Edition** is a personal fork of
[**keen-pbr**](https://github.com/maksimkurb/keen-pbr) by **maksimkurb** —
policy-based routing for Keenetic / OpenWrt / Debian routers. Same routing
engine, hardened for a weak Keenetic (MT7621) and reskinned in my own
cyberpunk style.

> **This is a personal fork.** For the real, maintained project — the one to
> install, star and report bugs to — go to
> **[maksimkurb/keen-pbr](https://github.com/maksimkurb/keen-pbr)**.
> Forest-PBR is not affiliated with or endorsed by keen-pbr, Keenetic or Netcraze.

Личный форк keen-pbr: тот же движок выборочной маршрутизации (VPN/WAN по
доменам, IP и портам), плюс пачка фиксов надёжности под слабый роутер и тёмный
киберпанк-веб в моём стиле.

## What Forest-PBR adds

**Reliability & performance**

- Skip redundant `dnsmasq` restarts — no DNS drops on every reload.
- Keep Keenetic HW NAT (fastnat) disabled so marked packets reach the `mangle`
  table instead of bypassing policy routing.
- Coalesce bursts of NDM netfilter events into a single firewall refresh.
- Config validation no longer rejects real-world lists (CIDRs in domain lists,
  wildcards, `host:port` — the parser skips them gracefully).

**Web UI**

- Bulk actions on every table, a list duplicate/overlap checker, multi-line
  rule conditions, concise "used in rule #N" hints, clearer interface pickers.
- Full **neon-cyberpunk retheme** — deep black, neon cyan, Space Grotesk +
  JetBrains Mono — dark by default.

The reliability and UX work is contributed back upstream as pull requests; the
cyberpunk skin and branding live only here, in Forest-PBR.

## Build

```bash
make          # host build
make test     # unit tests (doctest)
```

Router packages, install guides and full documentation — see the upstream
project: <https://keen-pbr.fyi/>

## Credits

- **Routing engine, daemon and the original web UI** —
  [keen-pbr](https://github.com/maksimkurb/keen-pbr) by **maksimkurb**.
  All credit for the core project goes there.
- **Forest-PBR Edition** — fork, reliability/UX fixes and cyberpunk skin by
  **rudywolf**.

## License

Licensed under **GPL-3.0**, the same license as upstream keen-pbr — see
[LICENSE](LICENSE). A fork can only stay GPL-3.0, and it does.
