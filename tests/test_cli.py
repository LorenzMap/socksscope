"""Help page, version, and the argument checks that run before the listener

The rejected input is kept as three tables - rules, options and --dns - because
every one of them is the same run: give socksscope the value, expect a non-zero
exit, the message that explains it, and no traceback.
"""
import pytest

from clients import run_cli, socksscope_module

module = socksscope_module()
parse_hostport = module.parse_hostport
parse_dns = module.parse_dns


# ── endpoint parsing ──────────────────────────────────────────────
@pytest.mark.parametrize("text,expected", [
    ("1080", ("127.0.0.1", 1080)),          # a bare port is the common case
    (":1080", ("127.0.0.1", 1080)),
    ("10.0.0.5:9050", ("10.0.0.5", 9050)),
    ("10.0.0.5", ("10.0.0.5", 1081)),       # a bare address keeps the default port
    ("proxy.local", ("proxy.local", 1081)),
    ("proxy.local:9050", ("proxy.local", 9050)),
    ("::1", ("::1", 1081)),                 # bare v6, all colons and no port
    ("[::1]:9050", ("::1", 9050)),
])
def test_listen_and_upstream_endpoints(text, expected):
    """Every -l and -u spelling should parse into a host and a port"""
    assert parse_hostport(text, 1081, "127.0.0.1") == expected


@pytest.mark.parametrize("text,expected", [
    ("u", ("upstream", None, None)),
    ("upstream", ("upstream", None, None)),
    ("l", ("local", None, None)),
    ("local", ("local", None, None)),
    ("u:10.0.0.53", ("upstream", ("10.0.0.53", 53), "tcp")),      # tcp is all u can do
    ("l:10.0.0.53", ("local", ("10.0.0.53", 53), "udp")),         # l has the choice
    ("l:10.0.0.53:tcp", ("local", ("10.0.0.53", 53), "tcp")),
    ("l:10.0.0.53:5353", ("local", ("10.0.0.53", 5353), "udp")),
    ("l:[::1]:5353:tcp", ("local", ("::1", 5353), "tcp")),
    ("l:::1", ("local", ("::1", 53), "udp")),                     # bare v6, all colons
])
def test_dns_spellings(text, expected):
    """Every --dns spelling should parse into a side, a server and a transport"""
    assert parse_dns(text) == expected


def test_the_defaults_can_be_written_out():
    """Writing the defaults out should parse the same as leaving them off, since
    ':53' and ':tcp' are what 'u:SERVER' means anyway"""
    assert parse_dns("u:8.8.8.8") == parse_dns("u:8.8.8.8:tcp") == parse_dns("u:8.8.8.8:53:tcp")
    assert parse_dns("l:8.8.8.8") == parse_dns("l:8.8.8.8:udp") == parse_dns("l:8.8.8.8:53:udp")


# ── the two help pages ────────────────────────────────────────────
FULL_ONLY = ("--upstream-auth", "--yes-resolve-rules", "--version", "--quiet",
             "--verbose", "--resolve-rules-every", "--rate-per-conn", "--queue-timeout")
ALWAYS = ("--listen", "--upstream", "--local", "--allow", "--block",
          "--resolve-rules", "--test-ruleset", "--dns", "--hosts",
          "--rate", "--max-conns")


@pytest.fixture(scope="module")
def help_pages():
    """Both pages, rendered once for every test that reads them"""
    short_code, short = run_cli("-h")
    full_code, full = run_cli("--help")
    assert short_code == 0 and full_code == 0, short + full
    return short, full


def test_both_pages_list_the_everyday_flags(help_pages):
    """Both help pages should carry every group and every everyday flag"""
    for page in help_pages:
        for group in ("ruleset:", "DNS:", "limits:"):
            assert group in page, group
        for flag in ALWAYS:
            assert flag in page, flag


def test_only_the_full_page_carries_the_tuning_flags(help_pages):
    """The tuning flags should show up in --help only - they still work, they are
    just not in the way of reading -h"""
    short, full = help_pages
    for flag in FULL_ONLY:
        assert flag in full, flag
        assert flag not in short, flag


def test_the_short_page_is_shorter_and_points_at_the_full_one(help_pages):
    """-h should be shorter than --help and point at it for the rest"""
    short, full = help_pages
    assert len(short.splitlines()) < len(full.splitlines())
    assert "--help' for the full help" in short
    assert "examples:" in full and "README" in full     # the reference is full-only
    assert "examples:" not in short


def test_version():
    """--version should print the program name and a version"""
    code, out = run_cli("--version")
    assert code == 0 and out.strip().startswith("socksscope.py ")


def test_hidden_flags_still_work():
    """A flag that -h does not list should still be accepted on the command line"""
    code, out = run_cli("--rate-per-conn", "32k", "--max-conns", "5", "--queue-timeout", "5",
                        "--test-ruleset", "1.2.3.4")
    assert code == 0, out


def test_flags_that_do_not_exist():
    """A flag we never had, or no longer have, should be refused as unrecognized
    -y is not a shortcut for --yes-resolve-rules: --resolve-rules sends queries
    into the engagement, so saying yes to it is spelled out rather than typed
    by reflex. The --dns spellings below were replaced by it and must stay gone."""
    for args in (("--resolve-rules", "-y", "--block", "corp.local"),
                 ("--upstream-dns", "10.0.0.53"), ("--upstream-tcp-dns", "10.0.0.53"),
                 ("--dns-tcp", "10.0.0.53"), ("--dns-udp", "10.0.0.53")):
        code, out = run_cli(*args, "--test-ruleset", "1.2.3.4")
        assert code != 0, args
        assert "unrecognized arguments" in out, out


# ── rules that are rejected ───────────────────────────────────────
@pytest.mark.parametrize("rule,expected", [
    # ports
    (":abc", "Bad rule"),
    (":70000", "port range"),
    (":0", "port range"),
    (":0-70000", "port range"),
    (":0-1024", "port range"),
    (":1024-1", "low to high"),          # used to parse fine and then match no port
    ("8080", ":8080"),                   # would otherwise become a rule for the name '8080'
    # addresses and ranges
    ("10.0.0.9-10.0.0.1", "Bad rule"),   # backwards, used to become a domain rule
    ("1.2.3.4-::1", "nonsensical range"),        # these came out as a traceback
    ("::1-1.2.3.4", "nonsensical range"),
    # every rule that is not a port, an address or a range used to fall through to
    #   'it must be a domain name'. A typo in --allow then restricted nothing at
    #   all, because only a parsed allow rule makes its own kind restricted
    ("10.0.0.0/33", "Bad rule"),
    ("::1/129", "Bad rule"),
    ("10.0.0.5:80", "Bad rule"),
    ("10.0.0.0/8,10.0.1.0/24", "Bad rule"),
    ("10.0.0.0 /8", "Bad rule"),
    ("host name", "Bad rule"),
    ("$(id)", "Bad rule"),
    ("bücher.de", "Bad rule"),
    ("a" * 300, "Bad rule"),
    ("@/nope/scope.txt", "Bad rule"),            # a scope file that is not there
    # '!' strips to an empty rule, which used to become the catch-all
    ("!", "empty rule"),
    ("!!", "empty rule"),
    # a star anywhere but in front parsed fine and built a rule that could never
    #   match. '**' and friends were worse: they stripped down to the catch-all,
    #   which matches everything and, unlike '*', looked resolvable to
    #   --resolve-rules. A leading dot means different things in no_proxy,
    #   cookies and firewalls, which is not a thing to guess at in a scope file
    ("abc.de.*", "is not a domain name"),
    ("abc.*.de", "is not a domain name"),
    ("ab*c.de", "is not a domain name"),
    ("*.abc.*.de", "is not a domain name"),
    ("**", "is not a domain name"),
    ("***", "is not a domain name"),
    ("**.", "is not a domain name"),
    ("*abc.de", "is not a domain name"),
    (".", "is not a domain name"),
    ("*.", "is not a domain name"),
    (".corp.local", "is not a domain name"),
])
def test_rejected_rules(rule, expected):
    """A rule we cannot use should result in a non-zero exit and an explanation,
    never in a traceback"""
    code, out = run_cli("--allow", rule, "--test-ruleset", "1.2.3.4")
    assert code != 0, f"{rule!r} was accepted"
    assert "Bad rule" in out and expected in out, out
    assert "Traceback" not in out, out


def test_a_scope_file_cannot_pull_in_another_one(tmp_path):
    """An '@FILE' inside a scope file should be refused rather than followed
    Only an --allow/--block value is read as a file; inside one the line is a
    rule like any other, so it has to fail loudly instead of being skipped"""
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.0/8\n@other-scope.txt\n")
    code, out = run_cli("--allow", f"@{scope}", "--test-ruleset", "1.2.3.4")
    assert code != 0, out
    assert "Bad rule" in out and "@other-scope.txt" in out, out
    assert "Traceback" not in out, out


def test_domain_name_rules_that_must_keep_working():
    """Every domain name rule we support should be accepted, catch-all included"""
    for rule in ("corp.local", "corp.local.", "*.corp.local", "*", "localhost",
                 "my-host.corp.local", "xn--bcher-kva.de", "_ldap._tcp.corp.local"):
        code, out = run_cli("--block", rule, "--test-ruleset", "1.2.3.4")
        assert code == 0, out


def test_an_all_numeric_name_is_warned_about_not_refused():
    """An all-numeric name should be warned about rather than refused
    These are syntactically legal labels, so they stay a domain name rule - but
    no all-numeric name resolves, and the address rules they were meant to be
    stay unrestricted, so the run has to say so out loud"""
    for rule in ("192.168.1.999", "1.2.3", "1.2.3.4.5", "01.02.03.04"):
        code, out = run_cli("--allow", rule, "--test-ruleset", "8.8.8.8:22")
        assert code == 0, out
        assert "warning" in out and "looks like you intended an IP" in out, out


def test_size_suffixes_accepted():
    """Every --rate size suffix should be accepted"""
    for value in ("1M", "512k", "1.5m", "4096"):
        code, out = run_cli("--rate", value, "--test-ruleset", "1.2.3.4")
        assert code == 0, out


# ── options that are rejected ─────────────────────────────────────
@pytest.mark.parametrize("args,expected", [
    # combinations that contradict each other
    (("--local", "-u", "1080"), "opposites"),               # --local used to win silently
    (("--local", "--upstream-auth", "user:pass"), "makes no sense with --local"),
    (("-v", "-q"), "--verbose and --quiet"),
    (("--resolve-rules", "--yes-resolve-rules", "--block", "host.corp.local"),
     "does not work with basic upstream resolving"),        # the upstream would resolve it
    # arguments that would quietly do nothing
    (("--yes-resolve-rules",), "only --resolve-rules asks"),
    (("--resolve-rules-every", "60"), "which is not on"),
    (("--queue-timeout", "5"), "only makes sense with --max-conns"),
    # values out of their range - a negative interval turns the refresh into a
    #   busy loop, 0 conns fell through as 'no limit' and -1 raised out of the
    #   Semaphore, and a rate of 0 used to read as falsy and mean 'unlimited'
    (("--resolve-rules", "--yes-resolve-rules", "--allow", "corp.local",
      "--resolve-rules-every", "-5"), "cannot be negative"),
    (("--max-conns", "5", "--queue-timeout", "-5"), "cannot be negative"),
    (("--max-conns", "0"), "at least 1"),
    (("--max-conns", "-1"), "at least 1"),
    (("--rate", "0"), "is not a rate"),
    (("--rate", "0.0001"), "is not a rate"),
    # '' used to reach text[-1] and raise IndexError instead of an argparse error
    (("--rate", ""), "is not a size like"),
    (("--rate", "abc"), "is not a size like"),
    (("--rate", "1x"), "is not a size like"),
    (("--rate", "M"), "is not a size like"),
    # '--upstream-auth bob' used to authenticate with an empty password
    (("-u", "1080", "--upstream-auth", "bob"), "USER:PASS"),
    (("--listen-auth", "bob"), "USER:PASS"),
    # endpoints that reached int() and came out as a traceback
    (("-l", "1081:abc"), "is not a port"),
    (("-u", "1080:abc"), "is not a port"),
    (("-l", "70000"), "is not a port"),
    (("-u", ":0"), "is not a port"),
    (("--test-ruleset", "1.2.3.4:abc"), "is not a port"),
])
def test_rejected_options(args, expected):
    """An option that contradicts another or falls outside its range should result
    in a non-zero exit and an explanation, never in a traceback"""
    code, out = run_cli(*args, "--test-ruleset", "1.2.3.4")
    assert code != 0, args
    assert expected in out and "Traceback" not in out, out


def test_empty_values_are_rejected():
    """An empty value should be refused by name: the loaders skip blank lines, so
    these used to vanish without a trace"""
    for flag in ("--listen", "--upstream", "--upstream-auth", "--listen-auth",
                 "--allow", "--block", "--hosts", "--test-ruleset"):
        code, out = run_cli(flag, "", "--test-ruleset", "1.2.3.4")
        assert code != 0, flag
        assert f"{flag} was given an empty value" in out, out


# ── --dns arguments that are rejected ─────────────────────────────
@pytest.mark.parametrize("value,expected", [
    # UDP cannot go through a SOCKS5 proxy, so it would leave the tunnel
    ("u:10.0.0.53:udp", "udp DNS does not work"),
    # a server without a side would silently decide whether the query leaves it
    ("10.0.0.53", "is not a valid --dns argument"),
    ("10.0.0.53:5353", "is not a valid --dns argument"),
    ("x:10.0.0.53", "is not a valid --dns argument"),
    ("l:tcp", "no DNS server"),
    ("u:udp", "no DNS server"),
    # resolving the resolver would need a resolver, so it has to be an address
    ("u:dns.corp.local", "is not an IP address"),
    # the port lands in parse_hostport, the same place -l and -u reach
    ("l:1.2.3.4:99999", "is not a SERVER[:PORT]"),
])
def test_rejected_dns_arguments(value, expected):
    """A --dns argument we cannot honour should result in a non-zero exit and an
    explanation, never in a traceback"""
    code, out = run_cli("--dns", value, "--test-ruleset", "1.2.3.4")
    assert code != 0, value
    assert expected in out and "Traceback" not in out, out


def test_the_upstream_side_needs_an_upstream():
    """'--dns u' without an upstream should be refused and point at '--dns local'"""
    code, out = run_cli("--local", "--dns", "u:10.0.0.53", "--test-ruleset", "1.2.3.4")
    assert code != 0 and "--dns local" in out
