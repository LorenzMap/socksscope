"""Domain name resolution: through the tunnel, left to the upstream, or --hosts

The upstream fixture's log doubles as the assertion: it records what socksscope
asked it to connect to, so a rewritten request (an address) is distinguishable
from a domain name that was passed straight through.
"""
import pytest

from clients import DENIED, OK, PAYLOAD, UNREACHABLE, fetch, free_port, parallel, socks5


def tunnelled(proxy, upstream, dns, *args):
    return proxy("-u", f"127.0.0.1:{upstream.port}",
                 "--dns", f"u:127.0.0.1:{dns.port}", *args)


# ── resolving through the tunnel ──────────────────────────────────
def test_name_is_resolved_and_rewritten(proxy, upstream, dns_server, target):
    """A name resolved here should reach the upstream as an address, never as a name"""
    dns = dns_server({"intranet.corp.local": ["127.0.0.1"]})
    p = tunnelled(proxy, upstream, dns, "--allow", "*.corp.local",
                  "--allow", "127.0.0.0/8", "--allow", f":{target.port}")

    assert fetch(p.port, "intranet.corp.local", target.port) == (OK, PAYLOAD)
    assert dns.asked("intranet.corp.local")
    # the upstream got the address, never the name
    assert f"127.0.0.1:{target.port}" in upstream.log
    assert "intranet.corp.local" not in upstream.log


def test_resolved_address_is_judged(proxy, upstream, dns_server, target):
    """An in-scope domain name pointing out of the IP scope should still be refused"""
    dns = dns_server({"evil.corp.local": ["8.8.8.8"]})
    p = tunnelled(proxy, upstream, dns, "--allow", "*.corp.local",
                  "--allow", "127.0.0.0/8")

    code, _ = socks5(p.port, "evil.corp.local", target.port)
    assert code == DENIED
    assert "dropped evil.corp.local: 8.8.8.8" in p.log
    assert "denied  evil.corp.local" in p.log
    assert "(all 1 resolved addresses not allowed by ruleset)" in p.log
    assert "8.8.8.8" not in upstream.log


def test_out_of_scope_addresses_are_dropped_not_fatal(proxy, upstream, dns_server, target):
    """An out-of-scope address should be dropped rather than fatal: one usable
    address among several is enough"""
    dns = dns_server({"mixed.corp.local": ["8.8.8.8", "127.0.0.1"]})
    p = tunnelled(proxy, upstream, dns, "--allow", "*.corp.local",
                  "--allow", "127.0.0.0/8", "--allow", f":{target.port}")

    assert fetch(p.port, "mixed.corp.local", target.port) == (OK, PAYLOAD)
    assert "dropped mixed.corp.local: 8.8.8.8" in p.log


def test_both_address_families_are_asked_for(proxy, upstream, dns_server, target):
    """Resolving should ask for A and AAAA, so that a v6-only name resolves at all
    and a dual-stack one is judged on both of its addresses
    One query carries one type and a resolver holding an A will not volunteer
    the AAAA, so a name used to be judged on its v4 addresses alone"""
    dns = dns_server({"dual.corp.local": ["127.0.0.1", "::1"],
                      "v6only.corp.local": ["::1"]})
    p = tunnelled(proxy, upstream, dns, "-v", "--block", "::1")

    code, sock = socks5(p.port, "dual.corp.local", target.port)  # the v4 one carries it
    sock.close()
    assert code == OK                                           # ::1 dropped, 127.0.0.1 kept
    assert socks5(p.port, "v6only.corp.local", 80)[0] == DENIED  # resolved, judged as v6
    # sorted: the two queries go out together, so which one lands first is a race
    for name in ("dual.corp.local", "v6only.corp.local"):
        assert sorted(q[1] for q in dns.asked(name)) == ["A", "AAAA"], name
    assert "resolved dual.corp.local -> 127.0.0.1 ::1" in p.log


def test_an_answer_without_an_address_is_unreachable(proxy, upstream, dns_server):
    """An answer that carries no address should result in UNREACHABLE
    Every way a server can answer without handing us one: the name does not
    exist, it exists with no A or AAAA, the server fails, or it answers a
    question we did not ask"""
    dns = dns_server({"empty.corp.local": [], "broken.corp.local": "SERVFAIL",
                      "liar.corp.local": "MANGLE"})
    p = tunnelled(proxy, upstream, dns)

    for name in ("nope.corp.local", "empty.corp.local",     # absent: NXDOMAIN
                 "broken.corp.local", "liar.corp.local"):
        assert socks5(p.port, name, 80)[0] == UNREACHABLE, name
    assert p.wait_for("no A or AAAA record")        # both families were asked
    assert "SERVFAIL" in p.log
    assert "does not match" in p.log                # the mangled answer was refused


def test_dead_dns_server_is_unreachable(proxy, upstream):
    """A DNS server that is not there should result in UNREACHABLE"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{free_port()}")
    assert socks5(p.port, "host.corp.local", 80)[0] == UNREACHABLE


def test_answers_are_cached(proxy, upstream, dns_server, target):
    # the name deliberately does not contain 'cached', which the log line below
    #   looks for - otherwise the assertion matches the name and proves nothing
    """A name asked for again should be answered from the cache, and the log should
    say which answer came off the wire and which off the cache"""
    dns = dns_server({"repeat.corp.local": ["127.0.0.1"]})
    p = tunnelled(proxy, upstream, dns, "-v")

    for _ in range(3):
        assert fetch(p.port, "repeat.corp.local", target.port) == (OK, PAYLOAD)
    assert len(dns.asked("repeat.corp.local")) == 2      # one A, one AAAA
    # and the log says which answer came off the wire and which off the cache
    resolves = [line for line in p.log.splitlines() if "resolved repeat.corp.local" in line]
    assert len(resolves) == 3, resolves
    assert "cached" not in resolves[0] and all("cached" in r for r in resolves[1:]), resolves


def test_simultaneous_requests_share_one_lookup(proxy, upstream, dns_server, target):
    """Requests that arrive together should share one lookup instead of each firing
    its own query"""
    dns = dns_server({"burst.corp.local": ["127.0.0.1"]})
    p = tunnelled(proxy, upstream, dns)

    def transfer(_):
        return fetch(p.port, "burst.corp.local", target.port)
    assert parallel(6, transfer) == [(OK, PAYLOAD)] * 6
    assert len(dns.asked("burst.corp.local")) == 2       # one A, one AAAA, shared by all six


def test_blocked_name_is_never_looked_up(proxy, upstream, dns_server):
    """A blocked name should be denied without a query reaching the server, since
    the verdict is already deny"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = tunnelled(proxy, upstream, dns, "--block", "admin.corp.local")

    assert socks5(p.port, "admin.corp.local", 80)[0] == DENIED
    assert not dns.asked("admin.corp.local")
    assert "denied  admin.corp.local:80 (block admin.corp.local)" in p.log


# ── what the log says about resolving ─────────────────────────────
def test_the_connect_line_names_the_address_that_answered(proxy, dns_server, target):
    """The connect line should name the address that carried the traffic
    The arrow used to list every candidate before a single one was tried, so the
    address that actually answered was never logged"""
    dns = dns_server({"two.corp.local": ["127.0.0.2", "127.0.0.1"]})
    p = proxy("--local", "-v", "--dns", f"l:127.0.0.1:{dns.port}:tcp")

    assert fetch(p.port, "two.corp.local", target.port) == (OK, PAYLOAD)
    arrow = [line for line in p.log.splitlines()
             if f"two.corp.local:{target.port} ->" in line][-1]
    assert arrow.endswith("-> 127.0.0.1"), arrow      # the one that answered, not both


def test_a_hosts_mapping_is_logged_as_a_resolve(proxy, target):
    """A --hosts mapping should be logged as a resolve: it never goes near DNS, but
    it is still where the name got its address"""
    p = proxy("--local", "-v", "--hosts", "mapped.corp.local=127.0.0.1")
    assert fetch(p.port, "mapped.corp.local", target.port) == (OK, PAYLOAD)
    assert "resolved mapped.corp.local -> 127.0.0.1 (--hosts" in p.log


def test_nothing_is_resolved_when_the_upstream_does_it(proxy, upstream, target):
    """Leaving the resolving to the upstream should write no resolve line here and
    hand the name over untouched"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "-v")
    assert fetch(p.port, "localhost", target.port) == (OK, PAYLOAD)
    assert "resolved localhost" not in p.log
    assert f"localhost:{target.port} -> localhost" in p.log    # src -> trg either way
    assert f"localhost:{target.port}" in upstream.log


# ── leaving it to the upstream ────────────────────────────────────
@pytest.mark.parametrize("rule", ["--allow", "--block"])
def test_ip_rules_warn_when_the_upstream_resolves(proxy, upstream, rule):
    """IP rules with upstream resolving should warn, for an allow and a block alike
    A block is dodged by a domain name just like an allow is, and it used to warn
    for neither - 'restricted' only collects the types that have an allow"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", rule, "10.0.0.0/8")
    assert "warning" in p.log and "IP address rules" in p.log


def test_a_blocked_network_is_reachable_by_name_when_the_upstream_resolves(proxy, target):
    """A blocked network should still be reachable by name when the upstream resolves
    What the warning is about: the address is never seen, so the block does not
    cover a name that resolves into it - by design, hence the warning"""
    up = proxy("--local", "--hosts", "secret.corp.local=127.0.0.1")
    p = proxy("-u", f"127.0.0.1:{up.port}", "--block", "127.0.0.0/8")

    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED     # judged
    assert fetch(p.port, "secret.corp.local", target.port) == (OK, PAYLOAD)   # not judged
    assert "warning" in p.log


def test_no_warning_when_we_resolve_ourselves(proxy, upstream, dns_server):
    """Resolving here should result in no warning: the addresses do get judged"""
    dns = dns_server({})
    p = tunnelled(proxy, upstream, dns, "--allow", "10.0.0.0/8")
    assert "warning" not in p.log


def test_name_rules_still_apply_when_the_upstream_resolves(proxy, upstream, target):
    """A name rule should still apply when the upstream does the resolving"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", "u", "--block", "localhost")
    assert socks5(p.port, "localhost", target.port)[0] == DENIED


# ── static mappings ───────────────────────────────────────────────
def test_mapping_is_used_instead_of_dns(proxy, upstream, dns_server, target):
    """A mapped name should be answered from --hosts and never reach the server"""
    dns = dns_server({"host.corp.local": ["8.8.8.8"]})
    p = tunnelled(proxy, upstream, dns, "--hosts", "host.corp.local=127.0.0.1")

    assert fetch(p.port, "host.corp.local", target.port) == (OK, PAYLOAD)
    assert not dns.asked("host.corp.local")               # never went to DNS


def test_mapping_works_without_any_dns(proxy, upstream, target):
    """A mapping should work without any DNS at all, and should re-enable the IP
    rules in pass-through mode"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}",
              "--hosts", "host.corp.local=127.0.0.1", "--allow", "127.0.0.0/8")
    assert fetch(p.port, "host.corp.local", target.port) == (OK, PAYLOAD)


@pytest.mark.parametrize("rules", [("--block", "host.corp.local"),   # by name
                                   ("--allow", "10.0.0.0/8")])       # by the address it maps to
def test_a_mapped_name_is_judged_like_any_other(proxy, target, rules):
    """A mapped name should be judged by its name and by the address it maps to"""
    p = proxy("--local", "--hosts", "host.corp.local=127.0.0.1", *rules)
    assert socks5(p.port, "host.corp.local", target.port)[0] == DENIED


def test_a_mapping_is_found_whatever_the_case(proxy, target):
    """A mapping should be found whatever the case of the requested name
    load_hosts() stores the name lowercased and the lookup used the raw name, so
    anything capitalised skipped the mapping and went to the real resolver"""
    p = proxy("--local", "--hosts", "intranet.corp.local=127.0.0.1")
    for host in ("intranet.corp.local", "INTRANET.corp.local", "Intranet.Corp.Local"):
        assert fetch(p.port, host, target.port) == (OK, PAYLOAD), host


def test_a_mapping_may_point_at_a_v6_address(proxy, target):
    """A mapping to a v6 address should be taken and judged as v6
    Both spellings accept one, and the address rules that judge it are the v6
    ones - nothing listens on ::1 here, so the block is what shows it arrived"""
    p = proxy("--local", "-v", "--hosts", "v6.corp.local=::1",
              "--hosts", "::1 second.corp.local", "--block", "::1")

    for name in ("v6.corp.local", "second.corp.local"):
        assert socks5(p.port, name, target.port)[0] == DENIED, name
        assert f"resolved {name} -> ::1 (--hosts" in p.log, p.log
    assert "dropped v6.corp.local: ::1 (block ::1)" in p.log


def test_both_mapping_syntaxes_work_in_a_file_and_on_the_command_line(proxy, target, tmp_path):
    """Both mapping syntaxes should work, mixed in one file and as an argument
    The '=' form and the /etc/hosts form may be mixed in one file, and the
    /etc/hosts form works on the command line too, not just in a file"""
    hosts = tmp_path / "hosts"
    hosts.write_text("# a comment\n"
                     "equals.corp.local=127.0.0.1\n"
                     "\n"
                     "127.0.0.1  spaced.corp.local second.corp.local   # inline comment\n")
    p = proxy("--local", "--hosts", f"@{hosts}", "--hosts", "127.0.0.1 inline.corp.local")

    for name in ("equals.corp.local", "spaced.corp.local", "second.corp.local",
                 "inline.corp.local"):
        assert fetch(p.port, name, target.port) == (OK, PAYLOAD), name


@pytest.mark.parametrize("entry,expected", [
    ("host.corp.local=nonsense", "Bad host mapping"),
    ("host.corp.local", "Bad host mapping"),
    ("1.2.3.4", "Bad host mapping"),
    ("=1.2.3.4", "Bad host mapping"),
    ("@/nope/hosts", "No such file"),
])
def test_bad_mappings_are_rejected(proxy, entry, expected):
    """A mapping that is not an address should stop the start rather than fail
    later, at connect time"""
    p = proxy("--local", "--hosts", entry, wait=False)
    p.proc.wait(timeout=10)
    assert p.proc.returncode != 0, entry
    assert "Bad host mapping" in p.log and expected in p.log, p.log


# ── asking a server ourselves ─────────────────────────────────────
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_a_local_server_is_asked_over_either_transport(proxy, dns_server, target, transport):
    """'l:SERVER' should resolve over udp and over tcp alike
    It is udp unless told otherwise; without an upstream there is no tunnel
    either way, so it just connects to the server itself"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]}, transport=transport)
    p = proxy("--local", "--dns", f"l:127.0.0.1:{dns.port}:{transport}",
              "--allow", "*.corp.local", "--allow", "127.0.0.0/8")

    assert fetch(p.port, "host.corp.local", target.port) == (OK, PAYLOAD)
    assert dns.asked("host.corp.local")


# ── resolving here while the data goes through the upstream ───────
def test_local_server_is_asked_outside_the_tunnel(proxy, upstream, dns_server, target):
    """'l:SERVER' with an upstream should send the query straight out while the
    data still goes through the tunnel"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]}, transport="udp")
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", f"l:127.0.0.1:{dns.port}",
              "--allow", "*.corp.local", "--allow", "127.0.0.0/8",
              "--allow", f":{target.port}")

    assert fetch(p.port, "host.corp.local", target.port) == (OK, PAYLOAD)
    assert dns.asked("host.corp.local")
    # the upstream carried the payload but was never asked to reach the DNS server
    assert f"127.0.0.1:{target.port}" in upstream.log
    assert f"127.0.0.1:{dns.port}" not in upstream.log


def test_system_resolver_can_be_used_with_an_upstream(proxy, upstream, target):
    """'--dns l' without a server should resolve here and still tunnel the data
    The gap that made --resolve-rules impossible behind a proxy without a server"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", "l",
              "--allow", "127.0.0.0/8", "--allow", f":{target.port}")

    assert fetch(p.port, "localhost", target.port) == (OK, PAYLOAD)
    # resolved here, so the upstream got the address instead of the name
    assert f"127.0.0.1:{target.port}" in upstream.log
    assert "localhost" not in upstream.log


# ── system resolver in local mode ─────────────────────────────────
@pytest.mark.parametrize("rule,expected", [("127.0.0.0/8", OK),      # what it resolves to
                                           ("10.0.0.0/8", DENIED)])  # and it is judged
def test_local_mode_uses_the_system_resolver(proxy, target, rule, expected):
    """--local should resolve through the system resolver and judge what it answers"""
    p = proxy("--local", "--allow", rule)
    code, sock = socks5(p.port, "localhost", target.port)
    sock.close()
    assert code == expected
