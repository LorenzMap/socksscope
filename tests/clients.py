"""Test helpers for socksscope.

Everything talks raw SOCKS5 rather than going through a client library: the
tests care about the exact reply byte (0x00 ok, 0x01 failure, 0x02 blocked by
the ruleset, 0x04 unreachable, 0x07 bad command, 0x08 bad address type), and a
library would flatten those into one generic error.

The other two moving parts are equally small on purpose:
* BulkServer - a TCP target that writes PAYLOAD bytes and closes, so a test can
  measure throughput without an HTTP stack in the way.
* DNSServer - a DNS/TCP responder with a fixed zone that records what it was
  asked, which is how the cache and --resolve-rules tests observe the
  queries socksscope did (or did not) send.

The tests were generated using Claude Opus 5 from my initial handwritten testcases. 
I manually checked most of them and made some adjustments. However, I was not
as diligent regarding code quality and style as with the main 'socksscope.py'
file.
"""
import os, pty, socket, socketserver, struct, subprocess, sys, threading, time
from pathlib import Path

import dns.message, dns.rcode, dns.rdatatype, dns.rrset

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "socksscope.py"
PY = sys.executable              # the venv interpreter that has our dependencies

PAYLOAD = 64 * 1024              # bytes BulkServer hands out per connection

# the SOCKS5 reply codes the tests tell apart, see the module docstring
OK, FAILED, DENIED, UNREACHABLE = 0x00, 0x01, 0x02, 0x04
BAD_COMMAND, BAD_ADDRESS = 0x07, 0x08


def socksscope_module():
    """socksscope.py imported as a module, to unit-test its pure helpers"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("socksscope", SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False


def socksscope_cmd():
    """Base argv, wrapped in `coverage run` when SOCKSSCOPE_COV is set"""
    if os.environ.get("SOCKSSCOPE_COV"):
        return [PY, "-m", "coverage", "run",
                "--rcfile", str(REPO / "pyproject.toml"), str(SRC)]
    return [PY, str(SRC)]


def proxy_with(overrides, *args, log_path=None):
    """socksscope with module constants overridden, for the waits a test cannot
    afford to sit out (HOST_QUIET, HALF_OPEN_TIMEOUT). Returns the Popen, which
    the caller stops; stderr goes to log_path when one is given."""
    settings = "; ".join(f"socksscope.{name} = {value}" for name, value in overrides.items())
    code = (f"import sys; sys.path.insert(0, {str(REPO)!r}); "
            f"import socksscope; {settings}; socksscope.main()")
    argv = [PY, "-c", code, *map(str, args)]
    if log_path is None:
        return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # opened in a with so only the child keeps the handle, as the proxy fixture does
    with open(log_path, "w") as log_file:
        return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=log_file)


def run_cli(*args):
    """Run socksscope once without a listener; returns (returncode, output)"""
    r = subprocess.run([*socksscope_cmd(), *map(str, args)],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def run_tty(answer, *args, timeout=30):
    """Run socksscope on a pty and answer its confirmation prompt

    --resolve-rules only prompts when there is a terminal, so run_cli() can
    never reach it; returns (returncode, output) like run_cli does.
    """
    parent, child = pty.openpty()
    proc = subprocess.Popen([*socksscope_cmd(), *map(str, args)],
                            stdin=child, stdout=child, stderr=child, text=True)
    os.close(child)
    os.write(parent, answer.encode())
    output = b""
    try:                             # a pty read raises EIO once the child is gone
        while chunk := os.read(parent, 4096):
            output += chunk
    except OSError:
        pass
    finally:
        os.close(parent)
    return proc.wait(timeout=timeout), output.decode(errors="replace")


# ── SOCKS5 ────────────────────────────────────────────────────────
def recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError(f"wanted {n} bytes, got {len(data)}")
        data += chunk
    return data


def greet(sock, auth=None):
    """The SOCKS5 greeting, optionally with 'user:pass' (RFC 1929).
    Returns the method byte the server picked, or the auth status when we
    ran the username/password exchange."""
    if auth is None:
        sock.sendall(b"\x05\x01\x00")               # we only offer 'no authentication'
        return recvall(sock, 2)[1]
    sock.sendall(b"\x05\x02\x00\x02")               # offer both, let the server choose
    method = recvall(sock, 2)[1]
    if method != 2:
        return method
    user, _, password = auth.partition(":")
    sock.sendall(b"\x01" + bytes([len(user)]) + user.encode()
                 + bytes([len(password)]) + password.encode())
    return recvall(sock, 2)[1]                      # 0 = accepted, anything else = refused


def socks5(proxy_port, host, port, atyp=None, cmd=1, timeout=15, auth=None):
    """Greet, CONNECT, return (reply_code, socket). The socket is only usable
    when the code is 0; the caller closes it either way."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout)
    sock.settimeout(timeout)
    assert greet(sock, auth) == 0, "the greeting was refused"

    if atyp is None:
        atyp = 1 if _is_v4(host) else (4 if ":" in host else 3)
    if atyp == 1:   address = socket.inet_aton(host)
    elif atyp == 4: address = socket.inet_pton(socket.AF_INET6, host)
    elif atyp == 3: address = bytes([len(host)]) + host.encode()
    else:           address = b""        # unknown type: the server must not read on
    sock.sendall(b"\x05" + bytes([cmd]) + b"\x00" + bytes([atyp])
                 + address + (struct.pack("!H", port) if address else b""))

    # our reply is always VER REP RSV ATYP=1 + 4 address bytes + 2 port bytes
    return recvall(sock, 10)[1], sock


def fetch(proxy_port, host, port, timeout=30, auth=None):
    """CONNECT through the proxy and drain the target; returns (code, bytes)"""
    code, sock = socks5(proxy_port, host, port, timeout=timeout, auth=auth)
    try:
        if code != 0:
            return code, 0
        total = 0
        while chunk := sock.recv(65536):
            total += len(chunk)
        return code, total
    finally:
        sock.close()


def _is_v4(host):
    try:
        socket.inet_aton(host)
        return host.count(".") == 3
    except OSError:
        return False


# ── servers the proxy points at ───────────────────────────────────
class _BulkHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"X" * self.server.payload)


class BulkServer:
    """TCP target: writes payload bytes to whoever connects, then closes

    payload=0 makes it accept and hang up without a byte, which is what an
    upstream that dies mid-handshake looks like from our side.
    """

    def __init__(self, payload=PAYLOAD):
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _BulkHandler)
        self.server.payload = payload
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class DNSServer:
    """DNS for a fixed zone, over TCP or UDP, recording every question it is asked.

    zone maps a name to a list of addresses; a name mapped to [] exists but has
    no records, a name that is absent gets NXDOMAIN. Two names misbehave on
    purpose, for the paths where the server answers but not usefully:
    "SERVFAIL" sets that rcode, "MANGLE" answers with a different question.
    """

    def __init__(self, zone, transport="tcp"):
        self.zone = {name.rstrip(".") + ".": addresses for name, addresses in zone.items()}
        self.queries = []
        outer = self

        if transport == "udp":
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    wire, sock = self.request
                    sock.sendto(outer._answer(wire), self.client_address)
            socketserver.ThreadingUDPServer.allow_reuse_address = True
            self.server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
        else:
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    # DNS/TCP frames every message with a two byte length prefix
                    (length,) = struct.unpack("!H", recvall(self.request, 2))
                    wire = outer._answer(recvall(self.request, length))
                    self.request.sendall(struct.pack("!H", len(wire)) + wire)
            socketserver.ThreadingTCPServer.allow_reuse_address = True
            self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)

        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _answer(self, wire):
        query = dns.message.from_wire(wire)
        name, rdtype = str(query.question[0].name), query.question[0].rdtype
        self.queries.append((name.rstrip("."), dns.rdatatype.to_text(rdtype)))

        response = dns.message.make_response(query)
        addresses = self.zone.get(name)
        if addresses == "SERVFAIL":
            response.set_rcode(dns.rcode.SERVFAIL)
        elif addresses == "MANGLE":
            response = dns.message.make_response(
                dns.message.make_query("somewhere.else.", rdtype))
        elif addresses is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            wanted = [a for a in addresses if (":" in a) == (rdtype == dns.rdatatype.AAAA)]
            if wanted:
                response.answer.append(dns.rrset.from_text_list(
                    name, 60, "IN", dns.rdatatype.to_text(rdtype), wanted))
        return response.to_wire()

    def asked(self, name):
        return [q for q in self.queries if q[0] == name]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def parallel(count, function):
    """Run function(index) in count threads; returns the results in order"""
    results = [None] * count
    def worker(index):
        results[index] = function(index)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=120)
    return results


def wait_until(predicate, timeout=5, interval=0.05):
    """Poll until predicate() is true; returns whether it made it"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
