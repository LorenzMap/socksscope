"""The ruleset itself, judged through --test-ruleset so no sockets are involved

The rules under test: domain name, IP and port are judged separately and all
three have to pass; the most specific rule wins and an exact tie goes to block;
whichever of the three has no allow rule at all is unrestricted.

--test-ruleset answers as many targets as it is given, in order, so one run
covers a whole table of them - which is what judge() below is for.
"""
from clients import run_cli, run_tty


def judge(rules, expected):
    """Check a {target: verdict} table against one ruleset in a single run

    Returns the output too, for the tests that also read what was printed.
    """
    targets = list(expected)
    code, out = run_cli(*rules, *[arg for target in targets
                                  for arg in ("--test-ruleset", target)])
    assert code in (0, 1), out              # 1 is a denied target, not a failed run
    verdicts = [line.split("=>", 1)[1].split()[0]
                for line in out.splitlines() if "=>" in line]
    assert len(verdicts) == len(targets), out
    assert dict(zip(targets, verdicts)) == dict(expected), out
    # the exit code carries the same verdict, so every rule test checks it too
    assert code == (0 if all(v == "ALLOW" for v in verdicts) else 1), out
    return out


# ── an empty ruleset ──────────────────────────────────────────────
def test_no_rules_allows_everything():
    """An empty ruleset should result in every name, address and port being allowed"""
    judge((), {"anything.example.com:445": "ALLOW", "8.8.8.8:22": "ALLOW"})


def test_a_trailing_dot_is_the_same_name():
    """A rule written with a trailing dot should judge the same as one without
    An FQDN copied out of a zone file used to build a rule that never matched"""
    judge(("--block", "corp.local."),
          {"corp.local:443": "DENY", "www.corp.local:443": "DENY"})
    judge(("--block", "*.corp.local."),
          {"corp.local:443": "ALLOW",              # subdomains only
           "www.corp.local:443": "DENY"})


# ── the catch-all '*' ─────────────────────────────────────────────
def test_star_blocks_every_domain_name():
    """'--block *' should refuse every domain name and still let literals through
    The answer to 'the upstream resolves, so IP rules never see a name': refuse
    names outright and every request has to carry an address"""
    judge(("--block", "*"),
          {"anything.example.com:443": "DENY", "corp.local:443": "DENY",
           "10.0.0.5:443": "ALLOW"})              # literals still pass


def test_star_ranks_below_every_named_rule():
    """The catch-all should lose every tie against a named rule, so that 'block
    everything except these' works - a single-label name used to rank the same
    and tie into block"""
    judge(("--block", "*", "--allow", "intranet.corp.local", "--allow", "localhost"),
          {"intranet.corp.local:443": "ALLOW", "localhost:443": "ALLOW",
           "other.corp.local:443": "DENY"})


def test_allowing_the_star_changes_nothing():
    """'--allow *' should be a noop rather than a deny-all: it allows what is
    allowed anyway and leaves the other rules to decide"""
    judge(("--allow", "*", "--block", "evil.com"),
          {"anything.example.com:443": "ALLOW", "evil.com:443": "DENY"})


# ── default deny, per rule kind ───────────────────────────────────
def test_allow_rule_restricts_only_its_own_kind():
    """One allow rule should restrict its own kind and leave the other two open"""
    judge(("--allow", "10.0.0.0/8"),
          {"10.0.0.7:443": "ALLOW",               # inside the one allowed network
           "8.8.8.8:443": "DENY",                 # ip rules now restrict
           "host.example.com:443": "ALLOW"})      # no name rules, still open


def test_all_three_kinds_must_pass():
    """A target should be allowed only when name, address and port all pass"""
    judge(("--allow", "*.corp.local", "--allow", ":443"),
          {"www.corp.local:443": "ALLOW",
           "www.corp.local:80": "DENY",           # port fails
           "www.other.com:443": "DENY"})          # name fails


# ── specificity: IP ───────────────────────────────────────────────
def test_the_finer_rule_wins_whichever_list_it_is_in():
    """The more specific rule should win, whether it is the allow or the block"""
    judge(("--block", "10.0.0.0/8", "--allow", "10.0.0.5"),
          {"10.0.0.5": "ALLOW", "10.0.0.9": "DENY"})
    judge(("--allow", "10.0.0.0/8", "--block", "10.0.0.5"),
          {"10.0.0.5": "DENY", "10.0.0.9": "ALLOW"})


def test_exact_tie_goes_to_block():
    """The same rule in both lists should result in a block"""
    judge(("--allow", "10.0.0.5", "--block", "10.0.0.5"), {"10.0.0.5": "DENY"})


def test_ip_ranges():
    """A range rule should cover both its ends and nothing outside them"""
    judge(("--allow", "192.168.1.10-192.168.1.50"),
          {"192.168.1.10": "ALLOW", "192.168.1.50": "ALLOW",
           "192.168.1.9": "DENY", "192.168.1.51": "DENY"})


def test_a_range_ranks_by_its_whole_size():
    """A range should rank by the size of the whole range, not of its pieces
    A range is stored as several prefixes, but it is one rule: every piece has
    to rank as the range's size, or a wide range cut into a stray /32 would
    outrank a genuinely narrower rule"""
    # 10.0.0.0-10.0.3.255 is 1024 addresses, summarised as a single /22, while
    #   10.0.1.0-10.0.1.255 is 256 and lands inside it
    judge(("--block", "10.0.0.0-10.0.3.255", "--allow", "10.0.1.0-10.0.1.255"),
          {"10.0.1.7": "ALLOW",                   # the narrower range wins
           "10.0.2.7": "DENY"})
    # and the same ranking against a plain network
    judge(("--block", "10.0.0.0/8", "--allow", "10.0.0.1-10.0.0.50"),
          {"10.0.0.7": "ALLOW", "10.9.9.9": "DENY"})


def test_an_awkward_range_ranks_as_one_rule():
    """A range that summarises into a dozen prefixes should still give one verdict
    10.0.0.1-10.0.0.254 fits no single prefix: it summarises into a dozen, from
    a /32 up to a /25. Ranking each piece on its own size would make the range
    win at 10.0.0.1 (a /32 piece) and lose at 10.0.0.100 (a /25 piece) against
    the same block - one rule with two different verdicts"""
    # the range covers 254, the block 64, so the block is the finer rule
    #   everywhere the two overlap - regardless of which piece matched
    judge(("--block", "10.0.0.0/26", "--allow", "10.0.0.1-10.0.0.254"),
          {"10.0.0.1": "DENY", "10.0.0.60": "DENY",
           "10.0.0.100": "ALLOW"})                # past the block, range alone


# ── specificity: domain names ─────────────────────────────────────
def test_more_labels_win():
    """The rule with more labels should win over a wildcard above it"""
    judge(("--block", "*.corp.local", "--allow", "vpn.corp.local"),
          {"vpn.corp.local": "ALLOW", "admin.corp.local": "DENY"})


def test_the_bare_domain_covers_the_apex_and_the_wildcard_does_not():
    """A bare domain rule should cover the apex and every subdomain, while '*.'
    should cover the subdomains only"""
    judge(("--allow", "corp.local"),
          {"corp.local": "ALLOW", "www.corp.local": "ALLOW",
           "deep.www.corp.local": "ALLOW"})
    judge(("--allow", "*.corp.local"),
          {"www.corp.local": "ALLOW", "corp.local": "DENY"})


def test_wildcard_beats_bare_domain_on_the_same_name():
    """'*.corp.local' should beat 'corp.local' on a subdomain: it matches strictly
    less, so it is the finer rule"""
    judge(("--allow", "corp.local", "--block", "*.corp.local"),
          {"www.corp.local": "DENY",
           "corp.local": "ALLOW"})                # the wildcard never matched


def test_domain_names_are_case_insensitive():
    """Capitals in the rule or in the target should make no difference"""
    judge(("--allow", "*.corp.local"), {"WWW.Corp.Local": "ALLOW"})
    judge(("--allow", "*.CORP.LOCAL"), {"www.corp.local": "ALLOW"})


def test_domain_names_with_dashes_are_not_ranges():
    """A dash in a domain name should not turn the rule into an address range"""
    judge(("--allow", "my-host.corp.local"),
          {"my-host.corp.local": "ALLOW", "other.corp.local": "DENY"})


# ── specificity: ports ────────────────────────────────────────────
def test_port_ranges():
    """A port range should cover both its ends and nothing above them"""
    judge(("--allow", ":8000-8100"),
          {"1.2.3.4:8000": "ALLOW", "1.2.3.4:8100": "ALLOW", "1.2.3.4:8101": "DENY"})


def test_a_single_port_beats_a_range_in_either_list():
    """A single port rule should beat a range, whichever list each one is in"""
    judge(("--allow", ":1-1024", "--block", ":445"),
          {"1.2.3.4:443": "ALLOW", "1.2.3.4:445": "DENY"})
    judge(("--block", ":1-1024", "--allow", ":443"),
          {"1.2.3.4:443": "ALLOW", "1.2.3.4:80": "DENY"})


# ── address families ──────────────────────────────────────────────
def test_the_families_are_judged_apart():
    """A rule for one address family should not judge an address of the other"""
    judge(("--allow", "0.0.0.0/0"), {"::1": "DENY"})       # a v4 rule is not a v6 rule
    judge(("--allow", "2001:db8::/32"),
          {"2001:db8::5": "ALLOW", "2001:dead::5": "DENY"})


def test_v6_rule_starting_with_a_colon_is_not_a_port():
    """A rule starting with a colon should still be read as v6, not as a port
    '::1' and '::/0' collide with the ':443' port syntax"""
    judge(("--block", "::1", "--allow", "::/0"), {"::1": "DENY", "::2": "ALLOW"})


def test_bracketed_target_with_a_port():
    """A bracketed v6 target should be split into its address and its port"""
    judge(("--allow", "2001:db8::/32", "--allow", ":443"),
          {"[2001:db8::5]:443": "ALLOW", "[2001:db8::5]:80": "DENY"})


# ── @file loading ─────────────────────────────────────────────────
def test_scope_file(tmp_path):
    """A @FILE should load one rule per line, honouring comments, blanks and '!'"""
    scope = tmp_path / "scope.txt"
    scope.write_text("""\
# engagement scope
*.corp.local

10.10.0.0/16
192.168.1.10-192.168.1.50
:8080
!192.168.1.42        # excluded host
""")
    judge(("--allow", f"@{scope}"),
          {"www.corp.local:8080": "ALLOW", "10.10.5.5:8080": "ALLOW",
           "192.168.1.20:8080": "ALLOW",
           "192.168.1.42:8080": "DENY",         # ! inverted it
           "192.168.1.60:8080": "DENY",
           "10.10.5.5:9090": "DENY"})           # port not listed


def test_the_exclamation_mark_flips_a_rule(tmp_path):
    """'!' should flip a rule into the other list, for every kind of rule
    It is a property of the entry, not of the file, so it works on the command
    line too - otherwise a scope file and its flags would disagree"""
    judge(("--allow", "10.0.0.0/8", "--allow", "!10.0.0.5",
           "--allow", "*.corp.local", "--allow", "!www.corp.local",
           "--allow", ":1-1024", "--allow", "!:445"),
          {"10.0.0.9:443": "ALLOW", "10.0.0.5:443": "DENY",
           "www.corp.local:443": "DENY",         # the name was flipped
           "other.corp.local:445": "DENY"})      # the port was flipped

    blocked = tmp_path / "block.txt"
    blocked.write_text("10.0.0.0/8\n!10.0.0.5\n")
    judge(("--block", f"@{blocked}"), {"10.0.0.9": "DENY", "10.0.0.5": "ALLOW"})


def test_file_and_flags_combine(tmp_path):
    """Rules from a @FILE and from the flags should end up in the same ruleset"""
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.0/8\n")
    judge(("--allow", f"@{scope}", "--block", "10.0.0.5"), {"10.0.0.5": "DENY"})


# ── the report --test-ruleset prints ───────────────────────────────
def test_a_mapped_name_is_judged_on_its_address_too():
    """A mapped name should be judged on its address too, and should stay allowed
    as long as one of its addresses passes
    The running tool resolves the name and applies the IP rules to the answer;
    --test-ruleset said ALLOW where the tool denied"""
    out = judge(("--hosts", "intranet.corp.local=127.9.9.9",
                 "--hosts", "many.corp.local=127.9.9.9",
                 "--hosts", "many.corp.local=127.0.0.5",
                 "--allow", "*.corp.local", "--allow", "127.0.0.0/24"),
                {"intranet.corp.local:443": "DENY", "many.corp.local:443": "ALLOW"})
    assert "dropped intranet.corp.local: 127.9.9.9" in out, out   # which address, and why


def test_the_report_lines():
    """Every shape of report line should say what decided it and where it points
    One run over all of them: the rule that turned a target down, where an
    allowed one would go, the words a default deny uses, the port that was
    stood in for, and a name that was never resolved pointing at itself"""
    out = judge(("--allow", "10.0.0.0/8", "--allow", "::/0",
                 "--allow", "*.corp.local", "--block", ":445"),
                {"10.0.0.5:445": "DENY",        # a rule turned it down
                 "10.0.0.5": "ALLOW",           # no port given, no name to resolve
                 "8.8.8.8": "DENY",             # nothing matched at all
                 "other.corp.local:443": "ALLOW",
                 "::1": "ALLOW"})
    assert "=> DENY  (block :445)" in out, out                  # names the deciding rule
    assert "not allowed by ruleset" in out, out                 # the same words the log uses
    assert "10.0.0.5:80" in out and "[::1]:80" in out, out      # the assumed port, brackets kept
    assert "=> ALLOW -> 10.0.0.5" in out, out                   # where it would go
    assert "=> ALLOW -> other.corp.local" in out, out           # unresolved: only itself


def test_the_assumed_port_is_judged_like_any_other():
    """A target without a port should be judged on the assumed 80 like any other"""
    judge(("--allow", "10.0.0.0/8", "--allow", ":443"), {"10.0.0.5": "DENY"})


def test_a_name_target_can_be_resolved_after_a_prompt(dns_server):
    """Answering the prompt with 'y' should resolve the target and judge the
    address, 'n' should leave the name unresolved and send nothing
    Offline the address is unknown, so --test-ruleset offers to look it up and
    judge it the way a real connection would - queries need a yes, like everywhere"""
    dns = dns_server({"far.corp.local": ["127.9.9.9"], "near.corp.local": ["127.0.0.1"]})
    args = ("--local", "--dns", f"l:127.0.0.1:{dns.port}:tcp",
            "--allow", "*.corp.local", "--allow", "127.0.0.0/24",
            "--test-ruleset", "far.corp.local:443", "--test-ruleset", "near.corp.local:443")

    code, out = run_tty("y\n", *args)
    assert code == 1, out                                # one of them is denied
    assert dns.asked("far.corp.local"), dns.queries
    assert "dropped far.corp.local: 127.9.9.9" in out, out   # judged on the address
    assert "=> DENY" in out and "=> ALLOW -> 127.0.0.1" in out, out

    asked = len(dns.queries)
    code, out = run_tty("n\n", *args)                    # declined: say what was skipped
    assert code == 0, out
    assert len(dns.queries) == asked, dns.queries        # nothing left the box
    assert "=> ALLOW -> far.corp.local" in out, out      # the name reaches only itself
    assert "you chose not to resolve" in out, out


def test_nothing_is_offered_when_there_is_nothing_to_look_up():
    # an address target needs no lookup
    """A target that needs no lookup should not be offered one, and leaving the
    resolving to the upstream should read as the configuration it is rather
    than as a declined prompt: no answer would have got the address judged"""
    code, out = run_cli("--local", "--allow", "10.0.0.0/8", "--test-ruleset", "10.0.0.5:443")
    assert code == 0 and "will actively query" not in out, out
    # --hosts already answers this name
    code, out = run_cli("--local", "--hosts", "target.corp.local=10.0.0.5",
                        "--allow", "10.0.0.0/8", "--test-ruleset", "target.corp.local:443")
    assert code == 0 and "will actively query" not in out, out
    # the upstream would do the resolving, so we have no resolver to offer - and
    #   that is a configuration, not a choice: no answer to any prompt would have
    #   got the address judged, so it has to read differently from a declined one
    code, out = run_cli("-u", "1080", "--allow", "*.corp.local", "--allow", "10.0.0.0/8",
                        "--test-ruleset", "www.corp.local:443")
    assert code == 0, out
    assert "the upstream resolves it" in out, out
    assert "you chose not to resolve the name" not in out, out
    assert "Send these queries" not in out, out


def test_no_queries_when_no_ip_rule_could_use_the_answer(dns_server):
    """A ruleset without IP rules should send no query and offer none
    A resolved address only changes the verdict when an IP rule judges it, so
    with none there is nothing to ask for and nothing to ask about"""
    dns = dns_server({"asked.corp.local": ["127.0.0.1"]})
    code, out = run_cli("--local", "--dns", f"l:127.0.0.1:{dns.port}:tcp",
                        "--allow", "*.corp.local", "--test-ruleset", "asked.corp.local:443")
    assert code == 0, out
    assert "query" not in out, out               # never even offered
    assert dns.queries == [], dns.queries        # and nothing left the box
    assert "not judged against the IP rules" not in out, out


def test_resolve_rules_notes_when_it_did_not_resolve():
    """--resolve-rules without a confirmation should note that address rules are
    missing, and without the flag there should be no such note
    Declined here because there is no terminal and no --yes-resolve-rules, so
    the expanded rules are absent and the verdict may disagree with the tool"""
    code, out = run_cli("--local", "--resolve-rules",
                        "--block", "admin.corp.local", "--allow", "10.0.0.0/8",
                        "--test-ruleset", "10.0.0.9")
    assert code == 0, out
    assert "chose not to resolve" in out
    assert "=> ALLOW" in out                 # the expanded block is not in yet

    _, out = run_cli("--allow", "10.0.0.0/8", "--test-ruleset", "10.0.0.9")
    assert "chose not to resolve" not in out          # nothing to note without the flag
