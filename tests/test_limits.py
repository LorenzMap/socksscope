"""Throttling and the connection cap

The timing bounds are deliberately loose: what matters is that a limit bites at
roughly the right magnitude, not that a test machine hits a stopwatch. The
buckets start full, so the first second of traffic is free - a transfer of
PAYLOAD at RATE takes about (PAYLOAD - RATE) / RATE seconds, not PAYLOAD / RATE.
"""
import socket
import threading
import time

from clients import (DENIED, FAILED, OK, PAYLOAD, fetch, free_port, parallel, port_open,
                     proxy_with, socks5, wait_until)

RATE = 32 * 1024                     # bytes/s -> PAYLOAD takes about a second
SLOW = 8 * 1024                      # slow enough to keep a slot busy


def timed(function, *args, **kwargs):
    start = time.monotonic()
    result = function(*args, **kwargs)
    return result, time.monotonic() - start


# ── baseline ──────────────────────────────────────────────────────
def test_unthrottled_is_fast(proxy, target):
    """A transfer with no limit set should finish right away"""
    p = proxy("--local")
    (result, elapsed) = timed(fetch, p.port, "127.0.0.1", target.port)
    assert result == (OK, PAYLOAD)
    assert elapsed < 2


# ── --rate ────────────────────────────────────────────────────────
def test_the_global_rate_is_one_bucket_for_every_connection(proxy, target):
    """--rate should slow a single transfer, and three of them sharing the one
    bucket should take about three times as long"""
    p = proxy("--local", "--rate", str(RATE))
    (result, one) = timed(fetch, p.port, "127.0.0.1", target.port)
    assert result == (OK, PAYLOAD)
    assert 0.5 < one < 6

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    results, three = timed(parallel, 3, transfer)

    assert all(r == (OK, PAYLOAD) for r in results)
    assert three > one * 1.8


# ── --rate-per-conn ───────────────────────────────────────────────
def test_a_per_connection_rate_gives_each_one_its_own_bucket(proxy, target):
    """--rate-per-conn should slow a single transfer the same way, but three at
    once should cost no more time, because none of them shares a bucket"""
    p = proxy("--local", "--rate-per-conn", str(RATE))
    (result, one) = timed(fetch, p.port, "127.0.0.1", target.port)
    assert result == (OK, PAYLOAD)
    assert 0.5 < one < 6

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    results, three = timed(parallel, 3, transfer)

    assert all(r == (OK, PAYLOAD) for r in results)
    assert three < one * 1.8


def test_both_rates_apply_to_the_same_connection(proxy, target):
    """--rate and --rate-per-conn together should both bite: one connection is
    held to the per-connection bucket and the shared one still adds up
    They are separate buckets and pipe() takes from every one it is given, so
    dropping either would show up as a transfer that is suddenly free"""
    p = proxy("--local", "--rate", str(RATE), "--rate-per-conn", str(RATE * 4))
    (result, one) = timed(fetch, p.port, "127.0.0.1", target.port)
    assert result == (OK, PAYLOAD)
    assert 0.5 < one < 6                           # the global bucket slowed it

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    results, two = timed(parallel, 2, transfer)
    assert all(r == (OK, PAYLOAD) for r in results)
    assert two > one * 1.5                         # and it is still shared


# ── --max-conns ───────────────────────────────────────────────────
def test_excess_connections_queue_instead_of_failing(proxy, target):
    """Connections over the cap should queue and still be served in full"""
    p = proxy("--local", "-v", "--max-conns", "2", "--rate-per-conn", str(RATE))

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    results = parallel(6, transfer)

    assert results == [(OK, PAYLOAD)] * 6          # every one served in full
    assert "waiting for a free slot" in p.log
    assert "denied " not in p.log


def test_cap_serialises_the_work(proxy, target):
    """One slot should result in the transfers running one after another"""
    p = proxy("--local", "--max-conns", "1", "--rate-per-conn", str(RATE))

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    _, capped = timed(parallel, 3, transfer)

    q = proxy("--local", "--rate-per-conn", str(RATE))
    def uncapped_transfer(_):
        return fetch(q.port, "127.0.0.1", target.port)
    _, uncapped = timed(parallel, 3, uncapped_transfer)

    assert capped > uncapped * 1.8


def test_a_denied_request_does_not_take_a_slot(proxy, target):
    """A denied request should take no slot: the ruleset runs before the queue, so
    refusals never fill it up"""
    p = proxy("--local", "-v", "--max-conns", "1", "--block", "127.0.0.1")
    for _ in range(4):
        assert socks5(p.port, "127.0.0.1", target.port)[0] == DENIED
    assert p.wait_for("denied ")                   # the run did get that far
    assert "waiting for a free slot" not in p.log  # -v, so the line would be there


# ── --queue-timeout ───────────────────────────────────────────────
def test_queue_timeout_gives_up(proxy, target):
    """A connection waiting longer than --queue-timeout should fail rather than hang"""
    p = proxy("--local", "-v", "--max-conns", "1", "--queue-timeout", "1",
              "--rate-per-conn", str(SLOW))

    holder = threading.Thread(target=fetch, args=(p.port, "127.0.0.1", target.port),
                              daemon=True)
    holder.start()
    assert p.wait_for(f"127.0.0.1:{target.port}")      # the first one holds the slot
    time.sleep(0.3)

    (code, _), elapsed = timed(socks5, p.port, "127.0.0.1", target.port)
    assert code == FAILED                              # not DENIED: this is not the ruleset
    assert elapsed < 5
    assert "gave up waiting for a slot" in p.log
    holder.join(timeout=30)


def test_queue_timeout_zero_waits(proxy, target):
    """--queue-timeout 0 should wait forever rather than give up at once, so a
    slow first transfer must not fail the one queued behind it"""
    p = proxy("--local", "--max-conns", "1", "--queue-timeout", "0",
              "--rate-per-conn", str(RATE))

    def transfer(_):
        return fetch(p.port, "127.0.0.1", target.port)
    assert parallel(2, transfer) == [(OK, PAYLOAD)] * 2


# ── half-open connections ─────────────────────────────────────────
class MuteServer:
    """Accepts and then says nothing and closes nothing, like a peer that hung"""

    def __init__(self):
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._held = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while True:
            try:
                self._held.append(self._listener.accept()[0])   # keep it open, say nothing
            except OSError:
                return

    def stop(self):
        self._listener.close()
        for sock in self._held:
            sock.close()


def test_a_half_open_connection_lets_go_of_its_slot(tmp_path):
    """A half-open connection should give its slot back on the deadline
    The client is done sending and the target never answers - without that
    deadline the pair keeps the only slot and every later client queues"""
    mute, port = MuteServer(), free_port()
    log = tmp_path / "halfopen.log"
    proc = proxy_with({"HALF_OPEN_TIMEOUT": 2}, "--local", "-l", f"127.0.0.1:{port}",
                      "--max-conns", "1", "--queue-timeout", "30", log_path=log)
    try:
        wait_until(lambda: port_open(port))
        time.sleep(0.2)

        code, holder = socks5(port, "127.0.0.1", mute.port)
        assert code == OK
        holder.shutdown(socket.SHUT_WR)                # done sending, target stays mute

        (code, later), elapsed = timed(socks5, port, "127.0.0.1", mute.port)
        assert code == OK, "the half-open connection never gave the slot back"
        assert 1 < elapsed < 20, elapsed             # released on the deadline, not the queue timeout
        later.close()
        holder.close()
        # and it says why it let go, rather than looking like a normal close
        assert wait_until(lambda: "after the other direction ended" in log.read_text())
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        mute.stop()
