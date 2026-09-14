# socksscope

[![PyPI](https://img.shields.io/pypi/v/socksscope)](https://pypi.org/project/socksscope/)
[![Python](https://img.shields.io/pypi/pyversions/socksscope)](https://pypi.org/project/socksscope/)
[![License](https://img.shields.io/pypi/l/socksscope)](https://github.com/LorenzMap/socksscope/blob/main/LICENSE)

A SOCKS5 front-end to better handle and restrict the scope of your traffic during
an engagement.

Wraps a SOCKS5 proxy you already have via --upstream, or acts as a new
SOCKS5 proxy with --local. Every CONNECT is judged against a ruleset of
domain names, addresses and ports that is specified as arguments at startup.

socksscope additionally allows you to pick where domain names are resolved and
which DNS server answers them. Through an existing SOCKS5 proxy only DNS via
TCP can be used for this. See section 'DNS and SOCKS5' below.

This tool utilizes [dnspython](https://github.com/rthalley/dnspython).

This is a pentesting tool. Only point it at systems and networks you are authorized
to test.

## Why this tool exists

- Four reasons to be honest (which are also my personal use-cases)
  - During engagements I always end up with a lot of SOCKS5 proxies (`ssh`,
    [`sshcatch`](https://github.com/LorenzMap/sshcatch), `chisel`, `ligolo`,
    or the C2 directly) so sometimes it makes sense to restrict some of them
    to the network they belong to in order to prevent mistakes (especially
    when coworkers are involved)
  - The network at the other end of a SOCKS5 proxy requires some unique DNS
    settings (just some specific hosts or a specific DNS server) that I don't
    want all other SOCKS5 proxies to share and I don't want to (or cannot)
    reconfigure the jumphost
  - When using a tool via `proxychains` where I can't find a way to deactivate
    telemetry or other default requests that otherwise are sent via the proxy
  - Also I did some experiments with AI agents and wanted to be sure to
    restrict the network connectivity (similar to the first coworker case I guess)

- My solution: `socksscope`
  - Open a (local) SOCKS5 proxy that wraps an existing SOCKS5 port or acts standalone
  - Allows you to restrict the connections made through it
    - Specify rules for **domain names, addresses and ports** on the command line or in a file
    - Rate limits and a connection cap that queues instead of dropping
  - Allows a flexible approach to DNS resolving
    - Specify a DNS server to use (also through the tunnel when DNS via TCP is available)
    - Specify domain name mappings like `/etc/hosts`

## Install

```
pipx install socksscope     # or: pip install socksscope
socksscope -h
```

Or from source:

```
git clone https://github.com/LorenzMap/socksscope
cd socksscope
pip install .
./socksscope.py -h
```

It is a single file with one dependency (`dnspython`), so copying `socksscope.py`
onto a host and installing `dnspython` works too.

Developed and tested on Python 3.12; needs at least 3.10.

## Examples

Wrap an SSH dynamic forward, resolve domain names through it and block every connection
except the ones in the private 10.0.0.0/8 network.

```
# Tunnel
ssh -ND 1080 user@jumphost

# Proxy
socksscope.py -l 1081 -u 1080 --dns u:10.0.0.53 --allow 10.0.0.0/8
13:10:11 listening on 127.0.0.1:1081 -> socks 127.0.0.1:1080, dns 10.0.0.53:53/tcp (upstream)
13:10:11   rule allow * (default)
13:10:11   rule allow :1-65535 (default)
13:10:11   rule allow 10.0.0.0/8
13:10:11
13:10:11 repeated connections to a host are counted, not logged
13:10:11 each host is summarised and reset 10s after it goes quiet
13:10:11 =====================
...

# Client (allowed if intranet.corp.local resolved to an address in 10.0.0.0/8)
proxychains curl http://intranet.corp.local/
# or
curl -x socks5h://127.0.0.1:1081 http://intranet.corp.local/
```

Allow web ports only on one domain name. WATCH OUT that this does not block
IP address connections to the IPs that the domain resolves to! (To restrict
that use explicit IP address rules or check the --resolve-rules example.)

```
socksscope.py -u 1080 --allow 'corp.local' --allow :80 --allow :443
13:11:24 listening on 127.0.0.1:1081 -> socks 127.0.0.1:1080, dns upstream
13:11:24   rule allow 0.0.0.0/0 (default)
13:11:24   rule allow ::/0 (default)
13:11:24   rule allow corp.local
13:11:24   rule allow :80
13:11:24   rule allow :443
13:11:24
13:11:24 repeated connections to a host are counted, not logged
13:11:24 each host is summarised and reset 10s after it goes quiet
13:11:24 =====================
...
```

Resolve the names on the local system but send the traffic through the
tunnel.

```
socksscope.py -u 1080 --dns l:8.8.8.8 --allow '*.corp.local' --allow :443
```

Standalone with rate and connection count restrictions.

```
socksscope.py --local --allow 10.10.0.0/16 --rate 1M --max-conns 20
```

Check a scope file against a few targets before trusting it.

```
socksscope.py --allow @scope.txt \
              --test-ruleset admin.corp.local:445 \
              --test-ruleset 10.10.0.7 \
              --test-ruleset 8.8.8.8:53
```

Only allow connections to the specified domains and enforce that ALSO
on IP addresses by resolving the domain name rules to their IP addresses.

```
socksscope.py -u 1080 --dns u:10.0.0.53 \
              --allow intranet.corp.local --allow fileserver.corp.local \
              --allow :443 --resolve-rules
```

## How it works

Configure socksscope using command line arguments. See `-h` (short help) and
`--help` (full help) as well as the examples section above.

#### Rules

With no rules at all nothing is restricted. `--block` rules obviously
block all connections to the specified domain names, addresses or ports
while everything else is allowed.
On the other hand `--allow` rules block everything except the domain
names, addresses or ports that are specified.
**Name, address and port are judged separately and all three have to pass.**
If multiple rules affect the same domain name, address or port, the rule
that is the most specific wins (deeper subdomain, smaller subnet).
An exact tie goes to block.

A rule is read from its shape:

| value                | means                                    |
| -------------------- | ---------------------------------------- |
| `corp.local`         | the domain name (and all its subdomains) |
| `*.corp.local`       | subdomains only (not the domain root)    |
| `*`                  | every domain name                        |
| `10.0.0.0/8`         | a network                                |
| `10.0.0.5`           | a single address                         |
| `10.0.0.1-10.0.0.50` | a range, both ends included              |
| `0.0.0.0/0`          | every IPv4 address                       |
| `fe80::/64`          | a network                                |
| `::/0`               | every IPv6 address                       |
| `:443`               | a port                                   |
| `:8000-8100`         | a port range, both ends included         |

`--allow` and `--block` arguments are repeatable as many times as you want.
You can specify a `@FILE` that loads a list of rules (one entry per line, `#`
comments, `!` to negate a rule).

```
# scope.txt given as '--allow @scope.txt'
corp.local
10.10.0.0/16
192.168.1.10-192.168.1.50
!192.168.1.42               # excluded host
:443
```

`--test-ruleset` shows the whole decision without opening a listener:

```
$ socksscope.py --local --allow 'corp.local' --allow :443 --block admin.corp.local \
    --test-ruleset www.corp.local --test-ruleset www.corp.local:443 --test-ruleset admin.corp.local:443
=====================

www.corp.local:80                  => DENY  (port not allowed by ruleset)
www.corp.local:443                 => ALLOW -> www.corp.local
admin.corp.local:443               => DENY  (block admin.corp.local)
```

When using `--test-ruleset` you may be asked whether DNS queries should be sent to
resolve the domain names. Read the question, think about whether queries like that are
acceptable in your engagement, and then answer.

#### DNS

This subsection describes what the different DNS arguments do. One important note
first:

**Where a domain name gets resolved decides how effective some rules are!**
For example, using an upstream SOCKS5 without specifying a `--dns` resolves the
domain names on the upstream, so socksscope cannot enforce its address rules for that
request. The section 'DNS and SOCKS5' below explains why this happens and why for
this upstream use-case only DNS via TCP can be used.

If you want to skip that problem entirely and don't need domain name resolution at all:
`--block '*'` refuses every domain name, so every request has to carry an address
and the address rules apply to all of them.

`--dns` says which side of the tunnel a domain name is resolved on and,
optionally, which server to ask over there:

```
--dns SIDE[:SERVER[:PORT][:tcp|udp]]
```

The side is `u` (`upstream`) or `l` (`local`). Without a `SERVER` the default
system configuration of the specified side is used. If `SERVER` is specified
socksscope queries the DNS itself.

| `--dns`            | who answers                         | the query goes                            | transport |
| ------------------ | ----------------------------------- | ----------------------------------------- | --------- |
| *(nothing)*        | `u`, or `l` with `--local`          |                                           |           |
| `u`                | the upstream's resolver             | upstream's default configuration          | -         |
| `l`                | local system's resolver             | local system's default configuration      | -         |
| `u:10.0.0.53`      | socksscope via 10.0.0.53            | through the tunnel                        | tcp       |
| `u:10.0.0.53:tcp`  | socksscope via 10.0.0.53            | through the tunnel                        | tcp       |
| `u:[::1]:5353:tcp` | socksscope via `::1` on port 5353   | through the tunnel                        | tcp       |
| `u:10.0.0.53:udp`  | refused, see 'DNS and SOCKS5' below |                                           |           |
| `l:8.8.8.8`        | socksscope via 8.8.8.8              | local system's network                    | udp       |
| `l:8.8.8.8:udp`    | socksscope via 8.8.8.8              | local system's network                    | udp       |
| `l:8.8.8.8:tcp`    | socksscope via 8.8.8.8              | local system's network                    | tcp       |
| `l:8.8.8.8:5353`   | socksscope via 8.8.8.8 on port 5353 | local system's network                    | udp       |

`SERVER` must be an address, never a domain name. Resolving the resolver would need
a resolver, and which side should answer *that* question is exactly the
confusion this argument exists to remove. Look it up once yourself instead:

```
dig +short dns.corp.local                    # from here
proxychains dig +tcp +short dns.corp.local   # from the other end of the tunnel
```

Additionally: The tool you use through socksscope has to hand the domain name to the proxy
instead of trying to resolve it itself. For example, use `socks5h://` with curl and set
`network.proxy.socks_remote_dns = true` in Firefox if you have trouble.

#### Hosts Mapping

`--hosts` is checked before all of the DNS handling and answers without any query. It takes
mappings of `name=ADDRESS` or `'ADDRESS name [name ...]'`. Files can be specified (similar to `/etc/hosts`).

```
--hosts intranet.corp.local=10.0.0.7
--hosts "10.0.0.8 db.corp.local db"
--hosts @hosts.txt
```

#### Resolve Rules

By default domain name rules only restrict the domain name and do not affect
IP address rules. For example, a host may be blocked by a domain name rule but
still be reachable by its IP.

`--resolve-rules` solves that. Every domain name rule is resolved at startup
and again at a fixed interval (`--resolve-rules-every`, 300s by default) so
socksscope can apply the addresses received as address rules. A blocked domain
name then blocks its addresses too. Works with `--test-ruleset` as well.
Resolving like this needs a resolver of our own, so anything but a plain
`--dns u`. Wildcard rules (`*.corp.local`, `*`) cannot be resolved and stay
name-only, socksscope says so at startup.

`--resolve-rules` results in active traffic to the specified DNS server! So it's
probably best to use it only against public DNS servers, or internal ones where you
know this is acceptable during an engagement. socksscope asks before it sends the
first queries, `--yes-resolve-rules` answers that prompt for you.

#### Connection Limits

`--rate` is one budget shared by all connections, `--rate-per-conn` gives every
connection its own. Both take bytes per second in a `1M` or `512k` style.

`--max-conns` caps how many connections run at the same time. The rest queue
instead of failing, a waiting client simply sits in the SOCKS5 handshake without
a reply until a slot frees up. `--queue-timeout` limits how long it waits there.

## DNS and SOCKS5

While the tool feels intuitive in most aspects (at least to me), one stands
out as confusing and I want to give some explanation for it.

The SOCKS5 protocol supports UDP, but most endpoints/servers do not (including
`ssh -D` for example) (2026-08). Accordingly, DNS requests through SOCKS5 proxies
are not sent as UDP requests from the client through the tunnel. Instead the
domain name itself is sent in place of an IP address in the CONNECT request. The
endpoint/server receives it, resolves the domain name using its own configuration
or cache, and then establishes the TCP connection to the destination.

For the domain name rules and host to IP mapping of socksscope this is fine
because we can simply read that domain name from the CONNECT request.

However, every time we want to actively resolve something through the tunnel
using our own local logic we are limited to DNS via TCP requests. This affects
the DNS queries of your tools as well as those from `--resolve-rules`, resulting
in the limitation that `--dns u:SERVER:udp` is refused at startup. Asking over UDP
means asking from here, which is `--dns l:SERVER` - the data still goes through
the upstream, only the query does not.

## Word of Warning

**socksscope is not a firewall or privacy tool.** It only sees what a client
sends through it. Nothing stops a client from opening a socket directly,
so the scope is enforced on the tools you point at it, not on the host.
While it's possible to use socksscope securely, it is a pentesting/redteaming
tool and NOT a privacy tool. There are a lot of ways to misconfigure socksscope!

**`--resolve-rules` can be noisy.** It queries every domain name rule again and
again in fixed intervals. That is fine against a public DNS server, but may
not be against an internal one that somebody is watching.

**It fails closed.** A domain name rule that cannot be resolved at startup stops
the tool, and so does a domain name rule that stays unconfirmable for three refresh
intervals. Better than judging traffic by an address we cannot verify.

## Options

`socksscope.py -h` prints a short help with the arguments needed to get going.
The full reference below is `socksscope.py --help`.

```
usage: socksscope.py [-h] [--help] [-l [HOST:]PORT] [--listen-auth USER:PASS]
                     [--local] [-u [HOST:]PORT] [--upstream-auth USER:PASS]
                     [-v] [-q] [--version] [--allow RULE] [--block RULE]
                     [--test-ruleset HOST[:PORT]] [--resolve-rules]
                     [--yes-resolve-rules] [--resolve-rules-every SEC]
                     [--dns SIDE[:SERVER[:PORT][:tcp|udp]]] [--hosts ENTRY]
                     [--rate SIZE] [--rate-per-conn SIZE] [--max-conns N]
                     [--queue-timeout SEC]

socksscope - a SOCKS5 front-end that lets you manage your traffic and keep it
inside your engagement scope. Can wrap an existing SOCKS5 port (--upstream)
or act independently (--local).

Every CONNECT is judged against a ruleset of domain names, addresses and ports,
given as arguments or in files at startup. Additionally you can specify a DNS
server to use and throttle connection speeds.

While it's possible to use socksscope securely, this is a pentesting/redteaming
tool and NOT a privacy tool. There are a lot of ways to misconfigure socksscope!
Watch out for unexpected rulesets when combining IP address and domain name rules.
(Check the README on Github for more information!)

options:
  -h                    show a short help message and exit
  --help                show the full help and exit
  -l [HOST:]PORT, --listen [HOST:]PORT
                        SOCKS5 port socksscope.py opens (default:
                        127.0.0.1:1081) - (restricted) SOCKS5 port where the
                        client programs connect to
  --listen-auth USER:PASS
                        optional credentials for the SOCKS5 port socksscope
                        opens
  --local               no SOCKS5 proxy to wrap, run socksscope.py
                        independently - connect out from this host while
                        enforcing the ruleset
  -u [HOST:]PORT, --upstream [HOST:]PORT
                        the existing SOCKS5 proxy that will be wrapped
                        (default: 127.0.0.1:1080)
  --upstream-auth USER:PASS
                        optional credentials for the upstream proxy
  -v, --verbose         log every connection with additional information
  -q, --quiet           log warnings only
  --version             show the version and exit

ruleset:
  --allow RULE          domain name, IP address or port rule to allow
                        (repeatable) - Rules: domain.tld | *.domain.tld | * |
                        IP | IP/NET | IP-IP | :PORT | :PORT-PORT - @FILE loads
                        a rules file - ranges include both ends - '!' inverts
                        a rule
  --block RULE          same as --allow but blocked instead (repeatable) -
                        syntax exactly like --allow
  --test-ruleset HOST[:PORT]
                        print how a target would be judged, then exit
                        (repeatable) - a target without a PORT is judged as
                        :80
  --resolve-rules       resolve domain name rules and apply them as IP address
                        rules (results in repeating queries)
  --yes-resolve-rules   answer the startup --resolve-rules confirmation with
                        yes
  --resolve-rules-every SEC
                        interval to re-resolve domain name rules (see
                        --resolve-rules) - if a domain name rule is
                        unconfirmed for three intervals socksscope exits - use
                        0 to resolve only once at startup (default: 300)

DNS:
  --dns SIDE[:SERVER[:PORT][:tcp|udp]]
                        specify where DNS queries should be resolved and what
                        protocol to use - check the README on Github for
                        explanations of all combinations - SIDE=[u|upstream]
                        to resolve through the wrapped SOCKS5 - SIDE=[l|local]
                        to resolve via the host socksscope is running on -
                        [:SERVER[:PORT]] optionally specify a DNS server -
                        [:tcp|:udp] optionally specify the DNS transport
                        protocol
  --hosts ENTRY         static mapping used before any DNS (like /etc/hosts)
                        (repeatable) - 'name=ADDRESS' or 'ADDRESS name' or
                        '@FILE' to load a list

limits:
  --rate SIZE           total bytes/s over all connections (e.g. 1M, 512k)
  --rate-per-conn SIZE  bytes/s for a single connection
  --max-conns N         connections to run at once - the rest queue instead of
                        failing
  --queue-timeout SEC   give up queueing after this long, 0 waits forever
                        (default: 60)

For more detailed examples, reasonings behind design decisions as well as an in-depth
explanation of socksscope's DNS resolving (especially when wrapping a SOCKS5 port and
actively resolving domain name rules using --resolve-rules) check the README on Github.

examples:
  socksscope.py -u 1080 --dns u:10.0.0.53 --allow @scope.txt
  socksscope.py -u 1080 --resolve-rules --allow 'intranet.corp.local' --allow :443
  socksscope.py --local --allow 10.0.0.0/8 --rate 1M --max-conns 20
  socksscope.py --allow @scope.txt --test-ruleset admin.corp.local:445
```

## Testing

- the test suite lives in `tests/` (pytest)
- run it from a virtualenv with the project and its dev dependencies installed
  (`pip install -e .`, then `pip install --group dev` on pip 25.1+ or simply
  `pip install pytest pytest-xdist coverage`)
- run it via `python -m pytest` or `tests/test.sh`, `-n 8` runs it in parallel
- for the coverage of the tests run `tests/test.sh cov`
- the throttling tests are timing based, so a busy machine can make them flap;
  re-run before believing a failure there

## License

MIT
