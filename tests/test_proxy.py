"""The SOCKS5 leg: local mode, chaining through an upstream, and reply codes"""
import asyncio
import logging
import signal
import socket
import struct
import time

from clients import (BAD_ADDRESS, BAD_COMMAND, BulkServer, DENIED, FAILED, OK, PAYLOAD,
                     fetch, free_port, greet, port_open, proxy_with, recvall, socks5,
                     socksscope_module, wait_until)


# ── --listen-auth ─────────────────────────────────────────────────
def test_listen_auth_lets_the_right_credentials_through_and_no_others(proxy, target):
    """The right credentials should be let through and every other client refused
    A refused client never reaches the ruleset, let alone the target"""
    p = proxy("--local", "--listen-auth", "bob:s3cret")
    assert fetch(p.port, "127.0.0.1", target.port, auth="bob:s3cret") == (OK, PAYLOAD)

    for wrong in ("bob:wrong", "eve:s3cret", "bob:", ":s3cret"):
        sock = socket.create_connection(("127.0.0.1", p.port))
        try:
            assert greet(sock, wrong) != 0, wrong          # status != 0 is a refusal
        finally:
            sock.close()
    assert p.wait_for("credentials missing or wrong")

    sock = socket.create_connection(("127.0.0.1", p.port))
    try:                    # only 'no authentication' offered: no method we can accept
        assert greet(sock) == 0xFF
    finally:
        sock.close()


def test_listen_auth_with_an_empty_username_still_authenticates(proxy, target):
    """An empty username should still count as configured credentials
    (None, None) means 'not configured'; an empty username is configured, so a
    truthiness test on the credentials would silently switch auth back off"""
    p = proxy("--local", "--listen-auth", ":s3cret")
    assert fetch(p.port, "127.0.0.1", target.port, auth=":s3cret") == (OK, PAYLOAD)
    assert "authenticated" in p.log            # the startup banner: auth is configured
    sock = socket.create_connection(("127.0.0.1", p.port))
    try:
        assert greet(sock) == 0xFF                  # 'no authentication' is still refused
    finally:
        sock.close()


def test_without_listen_auth_a_password_offer_still_gets_no_auth(proxy):
    """A client offering a password should get 'no authentication' when we do not
    ask for one, so clients that offer both keep working"""
    p = proxy("--local")
    sock = socket.create_connection(("127.0.0.1", p.port))
    try:
        sock.sendall(b"\x05\x02\x00\x02")
        assert recvall(sock, 2) == b"\x05\x00"
    finally:
        sock.close()
    assert "authenticated" not in p.log        # and the banner says auth is off


# ── local mode ────────────────────────────────────────────────────
def test_local_mode_ignores_the_upstream_default(proxy, target):
    """--local should serve on its own instead of trying to reach the -u default"""
    p = proxy("--local")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert "-> local" in p.log


def test_a_blocked_literal_names_the_rule_once(proxy, target):
    """A blocked address literal should be denied once, naming the rule
    One address, one verdict: it used to log a 'dropped' line and then a DENIED
    line that said less than the dropped one did"""
    p = proxy("--local", "--block", "127.0.0.0/8")
    assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED
    assert p.wait_for("denied ")
    assert "dropped" not in p.log
    assert f"denied  127.0.0.1:{target.port} (block 127.0.0.0/8)" in p.log


def test_a_default_deny_says_which_check_turned_it_down(proxy, target):
    """A default deny should name the check that turned it down
    Nothing matched, so there is no rule to name - name the check instead"""
    p = proxy("--local", "--allow", "10.0.0.0/8", "--allow", ":1")
    assert socks5(p.port, "192.168.1.1", target.port)[0] == DENIED
    assert p.wait_for("denied ")
    assert f"denied  192.168.1.1:{target.port} (port not allowed by ruleset)" in p.log, p.log


def test_port_is_checked_before_anything_else(proxy):
    """A blocked port should be denied before any lookup or connect is attempted,
    so an unreachable host is fine"""
    p = proxy("--local", "--block", ":445")
    code, _ = socks5(p.port, "10.255.255.1", 445)
    assert code == DENIED


def test_unreachable_target_reports_failure_not_denial(proxy):
    """A target nothing listens on should result in a failure, not a denial"""
    p = proxy("--local")
    code, _ = socks5(p.port, "127.0.0.1", free_port())
    assert code == FAILED


# ── chaining through an existing proxy ────────────────────────────
def test_chained_through_upstream(proxy, upstream, target):
    """A connection through -u should reach the target and show up in the upstream"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}",
              "--allow", "127.0.0.1", "--allow", f":{target.port}")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert f"127.0.0.1:{target.port}" in upstream.log


def test_upstream_auth_is_offered_and_a_refusal_is_reported(proxy, target):
    """--upstream-auth should be offered and accepted, while wrong credentials and
    none at all should each result in a failure that says why
    Two socksscopes are chained so the upstream actually demands credentials"""
    up = proxy("--local", "--listen-auth", "bob:s3cret")

    p = proxy("-u", f"127.0.0.1:{up.port}", "--upstream-auth", "bob:s3cret")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)

    wrong = proxy("-u", f"127.0.0.1:{up.port}", "--upstream-auth", "bob:wrong")
    assert socks5(wrong.port, "127.0.0.1", target.port)[0] == FAILED
    assert "rejected the credentials" in wrong.log

    # the upstream wants a password and this one was not given any to offer
    none = proxy("-u", f"127.0.0.1:{up.port}")
    assert socks5(none.port, "127.0.0.1", target.port)[0] == FAILED
    assert "accepted none of the authentication methods" in none.log


def test_upstream_auth_with_an_empty_username(proxy, target):
    """An empty username should still be offered to the upstream
    A truthiness test on the credentials would offer 'no authentication' here,
    and the upstream would refuse the handshake"""
    up = proxy("--local", "--listen-auth", ":s3cret")
    p = proxy("-u", f"127.0.0.1:{up.port}", "--upstream-auth", ":s3cret")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)


def test_upstream_failure_is_reported(proxy, target):
    """An upstream nothing listens on should result in a failure"""
    p = proxy("-u", f"127.0.0.1:{free_port()}")
    code, _ = socks5(p.port, "127.0.0.1", target.port)
    assert code == FAILED


def test_upstream_hanging_up_mid_handshake_is_reported(proxy, target):
    """An upstream that is not a SOCKS5 server should result in a failure that says
    the connection was closed without a reply"""
    dead = BulkServer(payload=0)
    try:
        p = proxy("-u", f"127.0.0.1:{dead.port}")
        assert socks5(p.port, "127.0.0.1", target.port)[0] == FAILED
        assert "closed the connection without replying" in p.log
    finally:
        dead.stop()


def test_ruleset_applies_before_the_upstream_is_touched(proxy, upstream, target):
    """A denied target should never reach the upstream at all"""
    p = proxy("-u", f"127.0.0.1:{upstream.port}", "--allow", "10.0.0.0/8")
    code, _ = socks5(p.port, "127.0.0.1", target.port)
    assert code == DENIED
    assert str(target.port) not in upstream.log


# ── protocol handling ─────────────────────────────────────────────
def test_an_address_is_judged_as_what_it_is_whatever_type_carries_it(proxy, target):
    """An address should be judged by the IP rules whatever type carried it
    Clients put IP literals in a DOMAIN-type request, and looking that 'name' up
    would NXDOMAIN - so it is judged as the address it is, v4 and v6 alike"""
    p = proxy("--local", "--allow", "127.0.0.1", "--allow", f":{target.port}")
    code, sock = socks5(p.port, "127.0.0.1", target.port, atyp=3)
    sock.close()
    assert code == OK

    blocked = proxy("--local", "--block", "127.0.0.1", "--block", "::1")
    assert socks5(blocked.port, "127.0.0.1", target.port, atyp=3)[0] == DENIED
    # no v6 target to reach, but the request must parse and be judged as v6
    assert socks5(blocked.port, "::1", 80, atyp=4)[0] == DENIED


def test_requests_we_do_not_support_are_refused(proxy, target):
    """BIND, UDP ASSOCIATE and an unknown address type should each be refused with
    their own reply code"""
    p = proxy("--local")
    assert socks5(p.port, "127.0.0.1", target.port, cmd=2)[0] == BAD_COMMAND   # BIND
    assert socks5(p.port, "127.0.0.1", target.port, cmd=3)[0] == BAD_COMMAND   # UDP ASSOCIATE
    assert socks5(p.port, "127.0.0.1", 80, atyp=5)[0] == BAD_ADDRESS          # address type


def test_non_socks5_greeting_is_dropped(proxy):
    """A greeting that is not SOCKS5 should be dropped without an answer
    The end-to-end half of read_handshake's unit test below: this one is about
    the listener really closing the socket, that one about the shapes it takes"""
    p = proxy("--local")
    sock = socket.create_connection(("127.0.0.1", p.port), 5)
    sock.sendall(b"\x04\x01\x00")            # SOCKS4
    assert sock.recv(16) == b""              # closed without an answer
    sock.close()


def test_client_vanishing_mid_transfer_is_survivable(proxy, target):
    """A client that drops mid-transfer should not take the proxy down with it"""
    p = proxy("--local", "--rate-per-conn", "8k")
    code, sock = socks5(p.port, "127.0.0.1", target.port)
    assert code == OK
    sock.recv(64)                            # take a little, then walk away
    sock.close()

    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)


def test_a_bare_port_listens_on_localhost(proxy, target):
    """'-l PORT' should listen on localhost
    It is the common case and used to bind a host named '1080'"""
    port = free_port()
    p = proxy("--local", "-l", str(port), listen=port)
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert f"listening on 127.0.0.1:{port}" in p.log


def test_a_bare_port_upstream(proxy, upstream, target):
    """'-u PORT' should dial the upstream on localhost"""
    p = proxy("-u", str(upstream.port))
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert f"socks 127.0.0.1:{upstream.port}" in p.log


# ── what startup reports ──────────────────────────────────────────
def test_startup_lists_the_rules_and_the_defaults(proxy):
    """Startup should list the rules as they were written, plus the types that are
    still wide open
    A type without an allow rule accepts everything, and IPv6 is the one people
    forget - an IPv4 rule does not restrict it and a block rule leaves it open"""
    p = proxy("--local", "--allow", "*.corp.local", "--allow", ":443",
              "--block", "10.0.0.1-10.0.0.50", "--block", ":445")
    assert "rule allow *.corp.local" in p.log
    assert "rule block :445" in p.log
    # the range is a dozen rules internally but must read as the one you wrote
    assert p.log.count("rule block 10.0.0.1-10.0.0.50") == 1
    # a block rule restricts nothing by itself, so both families stay wide open
    assert "rule allow 0.0.0.0/0 (default" in p.log
    assert "rule allow ::/0 (default" in p.log
    # both types that do have an allow rule are restricted, so no default for them
    assert "rule allow * (default)" not in p.log
    assert "rule allow :1-65535 (default)" not in p.log


def test_startup_says_when_nothing_is_restricted(proxy):
    """An empty ruleset should be reported out loud at startup"""
    p = proxy("--local")
    assert "no ruleset defined, everything is allowed" in p.log


def test_quiet_serves_without_saying_anything(proxy, target):
    """-q should silence the log without silencing the ruleset"""
    p = proxy("-q", "--local", "--allow", "127.0.0.1", "--allow", f":{target.port}")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert socks5(p.port, "10.0.0.1", target.port)[0] == DENIED    # still judged
    assert p.log == ""


def test_ctrl_c_does_not_wait_for_a_running_transfer(proxy, target):
    """Ctrl-C during a transfer should stop right away instead of waiting it out
    server.serve_forever() answers a cancellation by waiting for every open
    connection to finish, so Ctrl-C during a download used to hang until the
    download was done - here that would be the full throttled transfer"""
    p = proxy("--local", "--rate-per-conn", "8k")       # PAYLOAD takes ~7s at this rate
    code, sock = socks5(p.port, "127.0.0.1", target.port)
    assert code == OK
    sock.recv(64)                                       # the transfer is under way
    try:
        started = time.monotonic()
        p.proc.send_signal(signal.SIGINT)
        p.proc.wait(timeout=20)
        assert time.monotonic() - started < 3           # not ~7s, and not never
    finally:
        sock.close()
    assert "Task was destroyed but it is pending" not in p.log


def test_a_handler_task_stays_referenced_while_it_runs():
    """A handler should stay referenced while it runs and be dropped when it is done
    asyncio keeps only a weak reference to a handler task: the stream protocol
    drops its strong one in connection_lost() and all_tasks() is a WeakSet. A
    connection whose client and target both went away could then be garbage
    collected while still pending - 'Task was destroyed but it is pending!' -
    which also skipped handle()'s cleanup."""
    module = socksscope_module()
    module.UPSTREAM = None                          # local mode, nothing to dial out to
    module._RULESET = module.Ruleset(None, None)

    async def scenario():
        server = await asyncio.start_server(module.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")              # greet, then send no request
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x00"

        assert len(module._running) == 1, module._running   # parked on our request

        writer.close()                              # walk away mid-connection
        for _ in range(50):
            if not module._running:
                break
            await asyncio.sleep(0.05)
        assert module._running == set()             # the handler ran its cleanup
        server.close()

    asyncio.run(scenario())


# ── verbosity ─────────────────────────────────────────────────────
def test_connections_are_quiet_until_dash_v(proxy, target):
    """Connections should stay quiet until -v, while the verdicts should not
    Every connection costs two lines, so they live behind -v; what the ruleset
    did with them does not"""
    p = proxy("--local", "--block", "10.0.0.0/8")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert socks5(p.port, "10.0.0.1", target.port)[0] == DENIED

    assert p.wait_for("denied ")                       # the scope decision is not optional
    assert "closed after" not in p.log
    assert f"127.0.0.1:{target.port} ->" not in p.log


def test_quiet_still_reports_a_warning(proxy, upstream):
    """-q should still report a warning: it is not silence, and a ruleset that
    cannot do what it says still says so"""
    p = proxy("-q", "-u", f"127.0.0.1:{upstream.port}", "--allow", "10.0.0.0/8")
    assert p.wait_for("warning: probable unexpected ruleset")
    assert "listening on" not in p.log                # but the routine lines are gone


# ── the closing line ──────────────────────────────────────────────
def test_a_finished_connection_reports_what_moved(proxy, target):
    """A finished connection should report what moved and name no reason
    The open line said what we connected to, the closing one says what came of it"""
    p = proxy("--local", "-v")
    assert fetch(p.port, "127.0.0.1", target.port) == (OK, PAYLOAD)
    assert p.wait_for("closed after")
    closing = [line for line in p.log.splitlines() if "closed after" in line][-1]
    assert "received 64.0k" in closing, closing      # PAYLOAD, in --rate's own units
    assert "sent 0B" in closing, closing
    assert " - " not in closing, closing             # a clean end names no reason


def test_a_reset_is_named_instead_of_swallowed(proxy, target):
    """A connection that broke should name the reason instead of reading like a
    clean one
    pipe() used to 'except OSError: pass', so a connection that broke and one
    that finished looked exactly alike in the log"""
    p = proxy("--local", "-v", "--rate-per-conn", "8k")   # still running when we pull the plug
    code, sock = socks5(p.port, "127.0.0.1", target.port)
    assert code == OK
    sock.recv(64)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()                                     # RST, not a polite close

    assert p.wait_for("closed after", timeout=10)
    closing = [line for line in p.log.splitlines() if "closed after" in line][-1]
    assert " - " in closing, closing                 # it gave a reason
    assert "reset" in closing or "broken pipe" in closing, closing


def test_an_unexpected_error_is_named_in_full():
    """Known peer behaviour should get a word and anything else should be spelled
    out in full, because it is a bug or something new"""
    module = socksscope_module()
    assert module.closing_summary((10, None), (20, None)) == "sent 10B, received 20B"
    assert module.closing_summary((0, ConnectionResetError()), (0, None)) == \
        "sent 0B, received 0B - reset while sending"
    # one cause that took both directions reads as one reason
    assert module.closing_summary((0, ConnectionResetError()),
                                  (0, ConnectionResetError())) == "sent 0B, received 0B - reset"
    # the case that used to disappear entirely
    summary = module.closing_summary((5, None), (0, ValueError("chunk went missing")))
    assert summary == "sent 5B, received 0B - ValueError: chunk went missing while receiving"


def test_long_address_lists_are_trimmed():
    """A long list should be trimmed to a few entries and a count of the rest
    www.google.com answers with a dozen addresses and used to print all of them"""
    module = socksscope_module()
    assert module.head_elements(["a", "b", "c"], 4) == "a b c"
    assert module.head_elements(["a", "b", "c", "d", "e"], 3) == "a b c +2 more"
    assert module.head_elements(["a", "b", "c"], 3, ", ") == "a, b, c"
    assert module.head_elements([], 3) == ""


def test_verbose_trims_nothing():
    """-v should trim nothing, because it is for digging"""
    module = socksscope_module()
    module.LOG.setLevel(logging.DEBUG)
    assert module.head_elements(["a", "b", "c", "d", "e"], 3) == "a b c d e"


def test_byte_counts_use_the_units_rate_takes():
    """A byte count should be printed in the units --rate itself takes"""
    module = socksscope_module()
    assert [module.human(n) for n in (0, 999, 1024, 1536, 1024 ** 2, 3 * 1024 ** 3)] == \
        ["0B", "999B", "1.0k", "1.5k", "1.0M", "3.0G"]


# ── the client handshake ──────────────────────────────────────────
class _NullWriter:
    """Enough of a StreamWriter for read_handshake to answer a greeting"""
    def __init__(self): self.written = b""
    def write(self, data): self.written += data
    async def drain(self): pass


def handshake(payload, timeout=0.5):
    """Drive read_handshake over a reader that is never fed anything more, so
    a hang shows up as a TimeoutError instead of stalling the suite

    Returns (what it read, what it answered) - a client we drop must not be
    answered at all, which only the second half of that can show.
    """
    module = socksscope_module()

    async def drive():
        reader, writer = asyncio.StreamReader(), _NullWriter()
        reader.feed_data(payload)
        request = await asyncio.wait_for(
            module.read_handshake(reader, writer, "test"), timeout)
        return request, writer.written

    return asyncio.run(drive())


def test_a_non_socks5_client_is_dropped_without_reading_on():
    """A client that is not SOCKS5 should be dropped without reading on
    The second byte is a method count only if the first one says SOCKS5; 'E' of
    an HTTP verb is 69, which used to mean waiting for 69 bytes"""
    for payload in (b"GET / HTTP/1.1\r\n\r\n", b"hi\n", b"\x16\x03\x01\x00\x50"):
        assert handshake(payload) == (None, b""), payload      # and never answered


def test_a_socks5_client_is_read_as_before():
    """A SOCKS5 greeting and request should be read into command, type, host and port"""
    request = b"\x05\x01\x00\x01" + socket.inet_aton("10.0.0.5") + struct.pack("!H", 443)
    assert handshake(b"\x05\x01\x00" + request) == ((1, 1, "10.0.0.5", 443),
                                                     b"\x05\x00")   # 'no authentication'


def test_a_client_that_stops_mid_handshake_is_let_go(proxy):
    """A client that goes quiet mid-handshake should be let go on the timeout
    Valid so far and simply quiet, so only the clock can end it"""
    module = socksscope_module()
    p = proxy("--local", "-v")
    sock = socket.create_connection(("127.0.0.1", p.port), 5)
    sock.settimeout(module.HANDSHAKE_TIMEOUT + 10)
    try:
        sock.sendall(b"\x05\x01\x00")                 # greet, then send no request
        assert recvall(sock, 2) == b"\x05\x00"
        started = time.monotonic()
        assert sock.recv(16) == b""                   # closed on us
        assert module.HANDSHAKE_TIMEOUT - 1 < time.monotonic() - started < module.HANDSHAKE_TIMEOUT + 8
    finally:
        sock.close()
    assert p.wait_for("gave up on the handshake")


# ── what the default log level shows ──────────────────────────────
def collapsing(tmp_path, *args, quiet=2):
    """A proxy with a short HOST_QUIET, plus a handle on the log it writes"""
    port, log = free_port(), tmp_path / "collapse.log"
    proc = proxy_with({"HOST_QUIET": quiet}, "--local", "-l", f"127.0.0.1:{port}",
                      *args, log_path=log)
    wait_until(lambda: port_open(port))
    time.sleep(0.2)
    return port, proc, log


def test_a_burst_to_one_host_collapses_into_one_summary(tmp_path, target):
    """A burst to one host should collapse into one line per port and one summary
    Every connection at INFO would flood, so the first one is reported and the
    rest are counted up once the host goes quiet. Reaching :22 on a host already
    talking on :443 is worth knowing though, so the mute is per port - and the
    host still gets one summary rather than one per port"""
    other = BulkServer()
    port, proc, log = collapsing(tmp_path)
    try:
        for _ in range(3):
            assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert fetch(port, "127.0.0.1", other.port) == (OK, PAYLOAD)
        assert wait_until(lambda: "summary 127.0.0.1" in log.read_text(), timeout=15)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        other.stop()

    assert text.count(f"connect 127.0.0.1:{target.port}\n") == 1   # the repeats stayed quiet
    assert text.count(f"connect 127.0.0.1:{other.port}\n") == 1    # the new port did not
    assert text.count("summary 127.0.0.1:") == 1
    assert f"4 connections on :{target.port}, :{other.port}" in text
    assert f"received {PAYLOAD * 4 // 1024}.0k" in text            # every transfer counted


def test_a_host_is_reported_again_once_it_has_gone_quiet(tmp_path, target):
    """A host that has gone quiet should be reported again on its next connection,
    because the summary resets it"""
    port, proc, log = collapsing(tmp_path)
    try:
        assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert wait_until(lambda: "summary 127.0.0.1" in log.read_text(), timeout=15)
        assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert wait_until(lambda: log.read_text().count(f"connect 127.0.0.1:{target.port}\n") == 2,
                          timeout=15)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_a_resolved_name_names_the_address_a_literal_does_not(tmp_path, target):
    """A resolved name should carry an arrow to its address and a literal should not
    '10.0.0.5:443 -> 10.0.0.5' says nothing, so the arrow is only for names"""
    port, proc, log = collapsing(tmp_path, "--hosts", "host.corp.local=127.0.0.1")
    try:
        assert fetch(port, "host.corp.local", target.port) == (OK, PAYLOAD)
        assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert wait_until(lambda: "summary 127.0.0.1" in log.read_text(), timeout=15)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert f"connect host.corp.local:{target.port} -> 127.0.0.1\n" in text
    assert f"connect 127.0.0.1:{target.port}\n" in text                 # the literal, with no arrow


def test_ctrl_c_prints_a_session_summary(tmp_path, target):
    """Ctrl-C should print a summary of the whole session
    SIGINT, not the fixture's terminate(): only KeyboardInterrupt is caught"""
    port, proc, log = collapsing(tmp_path, "--allow", "127.0.0.0/8")
    try:
        assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert socks5(port, "10.0.0.5", target.port)[0] == DENIED
    finally:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)

    text = log.read_text()
    assert "session " in text and "1 connection, 1 denied" in text
    assert f"received {PAYLOAD // 1024}.0k" in text


def test_one_unreachable_line_instead_of_one_per_address(tmp_path):
    """A target that fails outright should be reported once, not once per address
    A name with a dead v6 address used to report a failure per connection even
    when the v4 one answered"""
    port, proc, log = collapsing(tmp_path, "--hosts", "dead.corp.local=127.0.0.1")
    dead_port = free_port()
    try:
        assert socks5(port, "dead.corp.local", dead_port)[0] == FAILED
        assert wait_until(lambda: "failed " in log.read_text(), timeout=10)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert f"failed  dead.corp.local:{dead_port}" in text
    assert "connect 127.0.0.1" not in text                      # that detail is -v only


def test_a_client_that_keeps_retrying_is_denied_once_per_port(tmp_path):
    """A client retrying a blocked host should be denied out loud once per port
    Browsers and dig retry a blocked host over and over and the verdict is the
    same every time, so only the first one is worth a line. Connects are muted
    per port, so denials are too - one rule covering two ports used to report
    only the first of them"""
    port, proc, log = collapsing(tmp_path, "--block", "10.0.0.5")
    try:
        for blocked in (80, 8080):
            for _ in range(3):
                assert socks5(port, "10.0.0.5", blocked)[0] == DENIED
        assert wait_until(lambda: "summary 10.0.0.5" in log.read_text(), timeout=15)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert text.count("denied  10.0.0.5:80 (block 10.0.0.5)") == 1     # retries stayed quiet
    assert text.count("denied  10.0.0.5:8080 (block 10.0.0.5)") == 1   # the other port did not
    assert "summary 10.0.0.5: 6 denied on :80, :8080 (block 10.0.0.5)" in text
    # nothing flowed, so the summary carries no byte counts to report
    assert not [line for line in text.splitlines() if "summary 10.0.0.5" in line
                and "sent" in line], text


def test_one_host_reports_its_connections_and_its_denials_together(tmp_path, target):
    """A host with connections and denials should get one summary covering both
    --allow :443 and a page trying :80 on the same host is the normal case, so
    the host gets one summary rather than two that may not be adjacent"""
    blocked = free_port()
    port, proc, log = collapsing(tmp_path, "--allow", "127.0.0.1", "--allow", f":{target.port}")
    try:
        assert fetch(port, "127.0.0.1", target.port) == (OK, PAYLOAD)
        assert socks5(port, "127.0.0.1", blocked)[0] == DENIED
        assert wait_until(lambda: "summary 127.0.0.1:" in log.read_text(), timeout=15)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert text.count("summary 127.0.0.1:") == 1
    assert (f"summary 127.0.0.1: 1 connection on :{target.port}, 1 denied on :{blocked}"
            in text), text


def test_a_second_reason_on_a_known_host_still_speaks_up(tmp_path):
    """A second reason on a host already being reported should still speak up
    Muting is not per host: a host that runs into a different check on another
    port is news, not a repeat"""
    port, proc, log = collapsing(tmp_path, "--allow", ":443", "--block", "10.0.0.5")
    try:
        assert socks5(port, "10.0.0.5", 80)[0] == DENIED        # the port rule
        assert socks5(port, "10.0.0.5", 443)[0] == DENIED       # the block rule
        assert wait_until(lambda: "summary 10.0.0.5" in log.read_text(), timeout=15)
        text = log.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert "denied  10.0.0.5:80 (port not allowed by ruleset)" in text
    assert "denied  10.0.0.5:443 (block 10.0.0.5)" in text
    assert "2 denied on :80, :443 (port not allowed by ruleset; block 10.0.0.5)" in text
