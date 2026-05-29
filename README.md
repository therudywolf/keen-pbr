# 🐺 keen-pbr — Forest-PBR Edition

[![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0-22c55e.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Edition](https://img.shields.io/badge/edition-Forest--PBR-67f0ff)](#)
[![keen-pbr core](https://img.shields.io/badge/keen--pbr_core-3.0.3-6b7280)](https://github.com/maksimkurb/keen-pbr)
[![target](https://img.shields.io/badge/target-Keenetic_MT7621-8b5cf6)](#)

**English** · [Русский](#-русский)

A **personal fork** of [**keen-pbr**](https://github.com/maksimkurb/keen-pbr) by
**maksimkurb** — policy-based routing (selective VPN/WAN by domain, IP and port).
This edition focuses the same engine on a single weak Keenetic (MT7621), adds
reliability fixes, live traffic observability and a self-healing routing helper,
and strips out everything that target doesn't need — all under a neon-cyberpunk skin.

> **Use the upstream, not this.** For the real, maintained, multi-platform
> project — to install, star and report bugs — go to
> **[maksimkurb/keen-pbr](https://github.com/maksimkurb/keen-pbr)**. Forest-PBR
> is a personal build, not affiliated with or endorsed by keen-pbr, Keenetic or Netcraze.

## ✨ How Forest-PBR differs from upstream

| Area | Upstream keen-pbr | **Forest-PBR Edition** |
|---|---|---|
| **Target** | Keenetic · OpenWrt · Debian, multi-arch | **Keenetic-only** (MT7621 / mipsel). OpenWrt + Debian packaging, aarch64 cross-build, the Hugo docs site and most CI removed — ~15k lines lighter. |
| **Firewall** | One `mangle` rule per list | **Consolidated** into `list:set` (`kpbrm_*`) rules — ~800 → ~20 rules, so a weak MT7621 copes (behaviour-identical when rules are grouped by outbound). |
| **Reliability** | stock | `fastnat=0` re-asserted on **every** NDM netfilter event (so HW-NAT can't bypass PBR); netfilter-event bursts coalesced into one refresh; **ListWarmer** background worker keeps `ipset`s warm past the dnsmasq cache; stale `[FASTNAT]` conntrack flushed **only** on real config change; IPv6 detection fallback; lenient list validation (CIDRs/wildcards/`host:port`); 120 s resolver-health poll. |
| **Observability** | — | `GET /api/metrics/traffic` + a **Metrics** page: live VPN-vs-WAN bytes/packets, **per-outbound and per-rule**. Optional rotating log file. |
| **Self-healing** | — | **Auto-heal** — one click promotes leaking domains into a top-priority `auto → VPN` list (the generalized "OpenAI-on-shared-CDN" fix). Default-off, stages a draft you confirm. |
| **Web UI** | stock | **Services** page (per-service VPN/WAN + one-click leak check & "check all"), **Metrics** dashboard, bulk table actions, list duplicate/overlap checker, regrouped nav (Overview / Routing / Settings), DNS screens removed, full **neon-cyberpunk** retheme (dark by default). |
| **DNS** | configurable in-app | Leans on the router's own dnsmasq (here: NextDNS-over-stubby DoT) — nothing to configure in the app, one less thing to misconfigure. |
| **Branding** | keen-pbr | FOR3ST cyberpunk skin, own README & version display. Still **GPL-3.0**, upstream attribution kept. |

Reliability/UX fixes are offered back upstream as pull requests; the
Keenetic-only lean and the cyberpunk skin live only here.

## Build

```bash
make            # host build (Docker toolchain)
make test       # unit tests (doctest)
```

Router `.ipk` packages are cross-built for `mipsel-3.4` via the Entware builder.
Install guides and full documentation for the engine live upstream:
<https://keen-pbr.fyi/>

## Credits

- **Routing engine, daemon and the original Web UI** —
  [keen-pbr](https://github.com/maksimkurb/keen-pbr) by **maksimkurb**. All
  credit for the core project goes there.
- **Forest-PBR Edition** — fork, Keenetic hardening, observability/self-healing
  and the cyberpunk skin by **rudywolf**.

## License

**GPL-3.0**, same as upstream keen-pbr — see [LICENSE](LICENSE). A fork can only
stay GPL-3.0, and it does; the upstream copyright and attribution are kept.

---

## 🇷🇺 Русский

[English](#-keen-pbr--forest-pbr-edition) · **Русский**

**Личный форк** [**keen-pbr**](https://github.com/maksimkurb/keen-pbr) от
**maksimkurb** — маршрутизация по политикам (выборочно VPN/WAN по доменам, IP и
портам). Эта редакция затачивает тот же движок под один слабый Keenetic
(MT7621), добавляет фиксы надёжности, живую наблюдаемость трафика и
самолечащийся помощник маршрутизации, и убирает всё, что этой цели не нужно —
всё в тёмном неон-киберпанк-стиле.

> **Ставьте оригинал, а не это.** За настоящим, поддерживаемым,
> мультиплатформенным проектом — чтобы установить, поставить звезду и сообщать о
> багах — идите в **[maksimkurb/keen-pbr](https://github.com/maksimkurb/keen-pbr)**.
> Forest-PBR — личная сборка, не аффилирована с keen-pbr, Keenetic или Netcraze.

### ✨ Чем Forest-PBR отличается от оригинала

| Область | Оригинал keen-pbr | **Forest-PBR Edition** |
|---|---|---|
| **Цель** | Keenetic · OpenWrt · Debian, много архитектур | **Только Keenetic** (MT7621 / mipsel). Пакеты OpenWrt и Debian, сборка под aarch64, сайт документации и почти весь CI убраны — минус ~15 тыс. строк. |
| **Файрвол** | По одному правилу `mangle` на список | **Свёрнуто** в правила `list:set` (`kpbrm_*`) — ~800 → ~20 правил, чтобы слабый MT7621 тянул (поведение идентично при группировке правил по выходу). |
| **Надёжность** | как есть | `fastnat=0` переустанавливается на **каждом** netfilter-событии NDM (чтобы HW-NAT не обходил PBR); всплески событий схлопываются в один пересбор; фоновый **ListWarmer** держит `ipset`-ы тёплыми мимо кеша dnsmasq; залипшие `[FASTNAT]` conntrack сбрасываются **только** при реальной смене конфига; фолбэк детекта IPv6; терпимая валидация списков (CIDR/маски/`host:port`); опрос здоровья резолвера раз в 120 с. |
| **Наблюдаемость** | — | `GET /api/metrics/traffic` + страница **«Метрики»**: живые байты/пакеты VPN vs WAN, **по выходам и по правилам**. Опциональный лог-файл с ротацией. |
| **Самолечение** | — | **Авто-список** — в один клик переносит утекающие домены в топ-приоритетный список `auto → VPN` (обобщённый фикс «OpenAI на общем CDN»). По умолчанию выключено, готовит черновик с подтверждением. |
| **Веб-интерфейс** | как есть | Страница **«Сервисы»** (VPN/WAN по сервису + проверка утечек и «проверить все»), дашборд **«Метрики»**, массовые операции в таблицах, проверка дублей/пересечений списков, перегруппировка меню (Обзор / Маршрутизация / Настройки), экраны DNS убраны, полный **неон-киберпанк** ретем (тёмная тема по умолчанию). |
| **DNS** | настраивается в приложении | Опирается на dnsmasq самого роутера (здесь: NextDNS поверх stubby DoT) — настраивать в приложении нечего, на одну поломку меньше. |
| **Брендинг** | keen-pbr | Киберпанк-скин FOR3ST, свой README и отображение версии. По-прежнему **GPL-3.0**, авторство upstream сохранено. |

Фиксы надёжности и UX предлагаются обратно в upstream через пул-реквесты;
заточка под Keenetic и киберпанк-скин живут только здесь.

### Сборка

```bash
make            # сборка под хост (Docker-тулчейн)
make test       # юнит-тесты (doctest)
```

Пакеты `.ipk` для роутера кросс-собираются под `mipsel-3.4` через Entware-builder.
Руководства по установке и полная документация движка — в upstream:
<https://keen-pbr.fyi/>

### Благодарности

- **Движок маршрутизации, демон и исходный веб-интерфейс** —
  [keen-pbr](https://github.com/maksimkurb/keen-pbr) от **maksimkurb**. Вся
  заслуга за ядро проекта — там.
- **Forest-PBR Edition** — форк, заточка под Keenetic, наблюдаемость/самолечение
  и киберпанк-скин от **rudywolf**.

### Лицензия

**GPL-3.0**, как и у upstream keen-pbr — см. [LICENSE](LICENSE). Форк может
оставаться только под GPL-3.0 — так и есть; копирайт и авторство upstream сохранены.
