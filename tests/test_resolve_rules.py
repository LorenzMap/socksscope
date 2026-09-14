"""--resolve-rules: domain rules also judged by the addresses they resolve to

The point of the feature is the IP-literal case. A domain name rule on its own
only catches a client that asks for it; a client that resolved it locally
(plain socks5://) sends an address and would otherwise be judged on IP alone.
"""
import time

from clients import DENIED, FAILED, OK, PAYLOAD, fetch, free_port, run_cli, run_tty, socks5


def expanding(proxy, upstream, dns, *args):
    return proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{dns.port}",
                 "--resolve-rules", "--yes-resolve-rules", *args)


# ── the confirmation ──────────────────────────────────────────────
def test_no_terminal_means_no_queries(proxy, upstream, dns_server):
    """--resolve-rules without a tty and without --yes-resolve-rules should refuse
    to start rather than resolve"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{dns.port}",
              "--resolve-rules", "--block", "host.corp.local", wait=False)
    p.proc.wait(timeout=10)

    assert p.proc.returncode != 0
    assert "--yes-resolve-rules" in p.log
    assert not dns.asked("host.corp.local")


def test_the_prompt_can_be_declined(upstream, dns_server):
    """Declining the prompt should send nothing and stop the run
    With a terminal it asks instead of erroring out"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    code, out = run_tty("n\n", "-u", f"127.0.0.1:{upstream.port}",
                        "--dns", f"u:127.0.0.1:{dns.port}",
                        "--resolve-rules", "--block", "host.corp.local")
    assert code != 0
    assert "Send these queries now?" in out
    assert "were declined" in out
    assert not dns.asked("host.corp.local")


def test_the_prompt_can_be_accepted(upstream, dns_server):
    """Accepting the prompt should resolve the rules and judge by their addresses"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    code, out = run_tty("y\n", "-u", f"127.0.0.1:{upstream.port}",
                        "--dns", f"u:127.0.0.1:{dns.port}",
                        "--resolve-rules", "--block", "host.corp.local",
                        "--test-ruleset", "127.0.0.1")
    assert code == 1, out                         # the target below is denied
    assert "Send these queries now?" in out
    assert dns.asked("host.corp.local")
    assert "=> DENY" in out and "(from host.corp.local)" in out


def test_the_confirmation_says_what_it_will_query_and_how_often(proxy, upstream, dns_server):
    """The confirmation should name what it will query, where it will ask, how
    often it repeats and how long a stale answer is kept"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "30",
                  "--block", "host.corp.local")
    assert "host.corp.local" in p.log                       # which name
    assert f"127.0.0.1:{dns.port} over TCP" in p.log        # and where it goes
    assert "every 30 seconds" in p.log and "after 90 seconds" in p.log


def test_confirmation_says_once_when_there_is_no_refresh(proxy, upstream, dns_server):
    """--resolve-rules-every 0 should be confirmed as a one-off at startup"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "0",
                  "--block", "host.corp.local")
    assert "resolved once, at startup" in p.log


def test_wildcards_are_reported_as_unresolvable(proxy, target, tmp_path):
    """A wildcard rule should be reported as unresolvable and otherwise left alone
    A bare '*' counts as one: it leaves no name behind, so it used to look
    resolvable and --resolve-rules tried to look up the empty string, which
    fails and takes the tool down"""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 host.corp.local\n")
    p = proxy("--local", "--hosts", f"@{hosts}", "--resolve-rules", "--yes-resolve-rules",
              "--allow", "*", "--allow", "*.other.local", "--allow", "host.corp.local")

    assert p.wait_for("wildcard")                  # reported, not resolved
    assert "allow *" in p.log and "*.other.local" in p.log
    assert "could not resolve" not in p.log
    assert fetch(p.port, "host.corp.local", target.port) == (OK, PAYLOAD)


def test_wildcards_only_is_rejected(proxy):
    """A ruleset of nothing but wildcards should be refused, since there is nothing
    to resolve and the flag would quietly do nothing"""
    p = proxy("--local", "--resolve-rules", "--yes-resolve-rules",
              "--allow", "*.corp.local", wait=False)
    p.proc.wait(timeout=10)
    assert p.proc.returncode != 0
    assert "not a wildcard" in p.log


# ── what the expansion does ───────────────────────────────────────
def test_blocked_domain_also_blocks_its_address(proxy, upstream, dns_server, target):
    """A blocked domain name should block its address too
    The bypass this closes: the client skips the name and asks for the IP"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--block", "admin.corp.local")

    assert socks5(p.port, "admin.corp.local", target.port)[0] == DENIED   # by name
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED          # by address
    assert "127.0.0.1 (from admin.corp.local)" in p.log


def test_allowed_domain_restricts_the_addresses(proxy, upstream, dns_server, target):
    """An allow rule that resolved should restrict which addresses are reachable"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--allow", "host.corp.local",
                  "--allow", f":{target.port}")

    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)   # the resolved one
    assert socks5(p.port, "127.0.0.2", target.port)[0] == DENIED      # anything else


def test_without_the_flag_the_address_is_not_covered(proxy, upstream, dns_server, target):
    """The same ruleset without --resolve-rules should let the literal slip past
    the name rule"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{dns.port}",
              "--block", "admin.corp.local")

    assert socks5(p.port, "admin.corp.local", target.port)[0] == DENIED
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)


def test_expanded_block_beats_a_broad_allow(proxy, upstream, dns_server, target):
    """A /32 from a blocked name should outrank an allowed network it sits inside"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--allow", "127.0.0.0/8",
                  "--block", "admin.corp.local", "--allow", f":{target.port}")

    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED
    # nothing listens on 127.0.0.2, so a connect failure rather than a denial
    #   is what proves the ruleset let it through
    assert socks5(p.port, "127.0.0.2", target.port)[0] == FAILED


def test_a_blocked_name_blocks_both_families(proxy, dns_server, target):
    """A blocked name should block its v4 and its v6 address
    Only the A record used to be expanded, so the v6 address of a blocked host
    stayed reachable behind the default 'allow ::/0'"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1", "::1"]})
    p = proxy("--local", "--dns", f"l:127.0.0.1:{dns.port}:tcp",
              "--resolve-rules", "--yes-resolve-rules", "--block", "admin.corp.local")

    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED
    assert socks5(p.port, "::1", target.port, atyp=4)[0] == DENIED


def test_bare_domain_rule_resolves_its_apex(proxy, upstream, dns_server, target):
    """A bare domain rule should resolve its apex, which has an address of its own"""
    dns = dns_server({"corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--block", "corp.local")

    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED


def test_startup_fails_when_a_rule_cannot_resolve(proxy, upstream, dns_server):
    """A rule that cannot resolve should stop the start, because it is a rule that
    would silently not apply"""
    dns = dns_server({})
    p = expanding(proxy, upstream, dns, "--block", "gone.corp.local")
    p.proc.wait(timeout=15)
    assert p.proc.returncode != 0


# ── keeping the addresses current ─────────────────────────────────
def test_rules_follow_a_changed_answer(proxy, upstream, dns_server, target):
    """A host that moves should be covered at its new address and released at its
    old one, because --resolve-rules-every re-queries"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "1",
                  "--block", "admin.corp.local")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED

    dns.zone["admin.corp.local."] = ["127.0.0.2"]
    assert p.wait_for("127.0.0.2 (from admin.corp.local)", timeout=10)

    assert socks5(p.port, "127.0.0.2", target.port)[0] == DENIED        # the new one
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)     # old one released


def test_a_blocked_domain_going_stale_stops_the_tool(proxy, upstream, dns_server, target):
    """A blocked domain that stops resolving should warn first and then stop the tool
    It may have moved to an address nothing is blocking now and we can no longer
    tell - so stop rather than leave it open"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "1",
                  "--block", "admin.corp.local")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED

    dns.zone["admin.corp.local."] = "SERVFAIL"
    p.proc.wait(timeout=30)
    assert p.proc.returncode != 0
    assert "keeping their previous addresses" in p.log        # warned first
    assert "for over 3s" in p.log                             # then gave up


def test_an_allowed_domain_going_stale_also_stops_the_tool(proxy, upstream,
                                                           dns_server, target):
    """An allowed domain going stale should stop the tool as well
    An allow rule going stale only over-restricts, but a rule nobody can verify
    is still not one to judge traffic by"""
    dns = dns_server({"host.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "1",
                  "--allow", "host.corp.local", "--allow", f":{target.port}")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)

    dns.zone["host.corp.local."] = "SERVFAIL"
    p.proc.wait(timeout=30)
    assert p.proc.returncode != 0


def test_a_blip_inside_the_grace_period_is_survived(proxy, upstream, dns_server, target):
    """One bad answer inside the grace period should be survived on the previous
    addresses, and a good answer after it should be picked up"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "2",
                  "--block", "admin.corp.local")

    dns.zone["admin.corp.local."] = "SERVFAIL"
    assert p.wait_for("keeping their previous addresses", timeout=15)
    assert p.proc.poll() is None                                  # still serving
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED  # on the old answer

    dns.zone["admin.corp.local."] = ["127.0.0.2"]                 # back, inside the grace
    assert p.wait_for("127.0.0.2 (from admin.corp.local)", timeout=15)
    assert p.proc.poll() is None
    assert socks5(p.port, "127.0.0.2", target.port)[0] == DENIED  # picked the new one up


def test_one_failing_name_does_not_drop_the_others(proxy, upstream, dns_server, target):
    """One failing name should keep its old addresses while every other name still
    updates, and only the broken one should be named"""
    dns = dns_server({"good.corp.local": ["127.0.0.1"], "bad.corp.local": ["127.0.0.2"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "2",
                  "--block", "good.corp.local", "--block", "bad.corp.local")

    dns.zone["bad.corp.local."] = "SERVFAIL"
    dns.zone["good.corp.local."] = ["127.0.0.3"]
    assert p.wait_for("keeping their previous addresses", timeout=15)

    # only the broken name is named, and the healthy one still moved
    assert "bad.corp.local" in p.log.split("could not re-resolve")[1].split("\n")[0]
    assert "good.corp.local" not in p.log.split("could not re-resolve")[1].split("\n")[0]
    assert "127.0.0.3 (from good.corp.local)" in p.log
    assert socks5(p.port, "127.0.0.2", target.port)[0] == DENIED   # bad kept its old one


def test_a_name_that_stops_resolving_loses_its_rules(proxy, upstream, dns_server, target):
    """A name that stops resolving should lose its rules and leave the tool serving
    NXDOMAIN is an answer, not a failure: the domain name has no address now"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "1",
                  "--block", "admin.corp.local")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED

    del dns.zone["admin.corp.local."]                    # now NXDOMAIN
    assert p.wait_for("no longer resolve", timeout=15)
    assert p.proc.poll() is None                         # not a failure, keep serving
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)


def test_an_unchanged_answer_is_not_logged_again(proxy, upstream, dns_server):
    """An answer that did not change should not be logged again on every refresh
    A steady state must not collect the same line once per interval forever.
    Run with -v, where the refreshes do show up - at the default level they are
    filtered by the level alone and this could not tell the difference."""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "-v", "--resolve-rules-every", "1",
                  "--block", "admin.corp.local")
    assert p.wait_for("resolved into 1", timeout=10)
    time.sleep(3)                                    # at least two more refreshes
    assert p.log.count("127.0.0.1 (from admin.corp.local)") > 1   # it did keep resolving
    assert p.log.count("resolved into 1") == p.log.count("debug: 1 domain name") + 1


def test_resolve_rules_every_zero_only_resolves_once(proxy, upstream, dns_server, target):
    """--resolve-rules-every 0 should resolve once and never look again"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--resolve-rules-every", "0",
                  "--block", "admin.corp.local")

    dns.zone["admin.corp.local."] = ["127.0.0.2"]
    assert not p.wait_for("127.0.0.2", timeout=3)
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED   # still the first answer


def test_resolving_here_works_behind_an_upstream(proxy, upstream, target):
    """'--dns l' should let --resolve-rules work behind an upstream
    It is the answer to 'the upstream resolves, so we never see an address'"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--dns", "l", "--resolve-rules",
              "--yes-resolve-rules", "--block", "localhost")

    assert p.wait_for("127.0.0.1 (from localhost)")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED


def test_mapped_names_need_no_dns_server_and_no_confirmation(proxy, upstream, target, tmp_path):
    """A name --hosts answers should need neither a resolver nor a confirmation
    Nothing leaves the box, so there is nothing to confirm - note the missing
    --yes-resolve-rules here"""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 mapped.corp.local\n")
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--hosts", f"@{hosts}",
              "--resolve-rules", "--block", "mapped.corp.local")

    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED
    assert "127.0.0.1 (from mapped.corp.local)" in p.log
    assert "will actively query" not in p.log


def test_confirmation_only_lists_names_that_need_a_query(proxy, upstream, dns_server,
                                                         tmp_path):
    """The confirmation should list only the names that still need a query"""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 mapped.corp.local\n")
    dns = dns_server({"asked.corp.local": ["127.0.0.1"]})
    p = expanding(proxy, upstream, dns, "--hosts", f"@{hosts}",
                  "--block", "mapped.corp.local", "--block", "asked.corp.local")

    assert "for 1 name(s)" in p.log
    # the names are the line under the header, and only the one needing a query
    lines = p.log.splitlines()
    listed = lines[next(i for i, line in enumerate(lines) if "name(s):" in line) + 1]
    assert "asked.corp.local" in listed and "mapped.corp.local" not in listed, listed


# ── --test-ruleset ─────────────────────────────────────────────────
def test_test_ruleset_can_resolve_and_then_agrees_with_the_tool(proxy, upstream,
                                                               dns_server, target):
    """--test-ruleset with a confirmation should resolve too, and its verdict
    should match what the running tool does with the same ruleset"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    args = ("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{dns.port}",
            "--resolve-rules", "--block", "admin.corp.local", "--allow", "127.0.0.0/8")

    code, out = run_cli(*args, "--yes-resolve-rules", "--test-ruleset", "127.0.0.1")
    assert code == 1, out
    assert "=> DENY" in out                       # the expanded /32 beats the /8
    assert "(from admin.corp.local)" in out
    assert "only to answer --test-ruleset" in out  # a one-off, not a running refresh
    assert dns.asked("admin.corp.local")

    # the running tool agrees
    p = proxy(*args, "--yes-resolve-rules")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED


def test_test_ruleset_without_confirmation_sends_nothing(upstream, dns_server):
    """--test-ruleset without a confirmation should send nothing and say so"""
    dns = dns_server({"admin.corp.local": ["127.0.0.1"]})
    code, out = run_cli("-u", f"127.0.0.1:{upstream.port}", "--dns", f"u:127.0.0.1:{dns.port}",
                        "--resolve-rules", "--block", "admin.corp.local",
                        "--test-ruleset", "127.0.0.1")
    assert code == 0 and "chose not to resolve" in out
    assert not dns.asked("admin.corp.local")


def test_test_ruleset_reports_a_resolver_it_cannot_reach(upstream):
    """A resolver --test-ruleset cannot reach should be reported: a scope check
    that cannot resolve its own rules is not a scope check"""
    code, out = run_cli("-u", f"127.0.0.1:{upstream.port}",
                        "--dns", f"u:127.0.0.1:{free_port()}",
                        "--resolve-rules", "--yes-resolve-rules", "--block", "admin.corp.local",
                        "--test-ruleset", "127.0.0.1")
    assert code != 0
    assert "admin.corp.local" in out and "Traceback" not in out

