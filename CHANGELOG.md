# Changelog

All notable changes to **socksscope** are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-13

Initial version published on GitHub and PyPI. The 0.1.x series was developed
internally and never released.

### Added

- **A SOCKS5 front-end in a single file.** Wraps a SOCKS5 proxy that already exists
  (`-u` / `--upstream`) or connects out on its own (`--local`), and opens its own
  restricted SOCKS5 port (`-l` / `--listen`, default `127.0.0.1:1081`). Credentials on
  both ends are optional (`--listen-auth`, `--upstream-auth`).
- **A ruleset over domain names, addresses and ports.** `--allow` and `--block` are
  repeatable and read a rule from its shape: `domain.tld`, `*.domain.tld`, `*`, `IP`,
  `IP/NET`, `IP-IP`, `:PORT` and `:PORT-PORT`, with ranges including both ends. `@FILE`
  loads a rules file (`#` comments, `!` inverts a rule). Name, address and port are
  judged separately and all three have to pass. The most specific rule wins (deeper
  subdomain, smaller subnet) and an exact tie goes to block.
- **`--test-ruleset HOST[:PORT]`** prints how a target would be judged and exits, without
  opening a listener, so a scope file can be checked before it is trusted.
- **`--dns SIDE[:SERVER[:PORT][:tcp|udp]]`** decides which side of the tunnel resolves a
  domain name and, optionally, which server answers it. `u`/`upstream` and `l`/`local`
  select the side. Naming a `SERVER` makes socksscope query it itself.
- **`--hosts`** static mappings that are answered before any DNS happens, as
  `name=ADDRESS`, `'ADDRESS name [name ...]'` or `@FILE`.
- **`--resolve-rules`** resolves every domain name rule and applies the addresses as
  address rules too, so a blocked name also blocks the addresses behind it. Rules are
  re-resolved every `--resolve-rules-every` seconds (default 300, `0` resolves once).
  **It fails closed:** a rule that cannot be resolved at startup, or that stays
  unconfirmable for three intervals, stops the tool. Because this produces repeating
  queries, socksscope asks before the first ones; `--yes-resolve-rules` answers that prompt.
- **Connection limits.** `--rate` is one byte/s budget shared by all connections,
  `--rate-per-conn` gives each connection its own. `--max-conns` caps how many run at
  once and queues the rest instead of failing them. A waiting client sits in the
  SOCKS5 handshake until a slot frees up, bounded by `--queue-timeout` (default 60s,
  `0` waits forever).
- **Summarising connection logging.** Repeated connections to a host are counted rather
  than logged, and each host is summarised and reset once it has been quiet for 10s.
  `-v` logs every connection with more detail, `-q` logs warnings only.
- **A two-tier help.** `-h` prints a short usage summary, `--help` the full reference.
- **A pytest suite in `tests/`** (159 test functions)
- **Packaging.** Installable from PyPI as `socksscope` with a `socksscope` console script.
  Needs Python 3.10 or newer and has one runtime dependency, `dnspython`.
