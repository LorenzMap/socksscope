#!/usr/bin/env python3
"""
socksscope - a SOCKS5 front-end that lets you manage your traffic and keep it
inside your engagement scope. Can wrap an existing SOCKS5 port or act independently.
"""

import argparse
import asyncio
import contextlib
import enum
import hmac
import ipaddress
import logging
import re
import socket
import struct
import sys
import time
from pathlib import Path

import dns.asyncquery, dns.message, dns.rcode, dns.rdatatype

__version__ = "0.2.0"


LISTEN        = ("127.0.0.1", 1081)    # the SOCKS5 we open
LISTEN_AUTH   = (None, None)           # (user, pass) bytes we demand from our own clients
UPSTREAM      = ("127.0.0.1", 1080)    # SOCKS5 proxy to relay through, None = connect out ourselves
UPSTREAM_AUTH = (None, None)           # (user, pass) for the upstream, if it wants them
DNS_SIDE      = "upstream"             # which side of the tunnel resolves, 'upstream' or 'local'
DNS_SERVER    = None                   # (address, port) we query ourselves, None = that side resolves
DNS_TRANSPORT = None                   # 'tcp' or 'udp' towards DNS_SERVER
HOSTS         = {}                     # static domain name -> [address, ...] mappings
RESOLVE_RULES = False                  # turn the domain name rules into address rules too
RESOLVE_RULES_EVERY = 300              # seconds between re-resolving rules, 0 = only once
RATE_PER_CONN = 0                      # bytes/s per connection, 0 = unlimited
QUEUE_TIMEOUT = 60                     # seconds a connection waits for a free slot

TTL_MIN, TTL_MAX = 30, 3600            # clamp cached DNS TTLs into this range
NEG_TTL = 30                           # how long a "no such record" is remembered
CONNECT_TIMEOUT = 10                   # seconds for a connect or a lookup
HANDSHAKE_TIMEOUT = 10                 # seconds a client gets to send its handshake
HALF_OPEN_TIMEOUT = 60                 # seconds a connection is held on after one side saw EOF
HOST_QUIET = 10                        # seconds without a connection to a host before its summary is printed

_RULESET = None                        # the Ruleset built from --allow/--block
_RATE = None                           # global TokenBucket shared by all connections
_SLOTS = None                          # asyncio.Semaphore for --max-conns
_running = set()                       # strong refs to the live handle() connection tasks
_resolved_log = None                   # last --resolve-rules summary, to only log changes
_cache: dict[str, tuple[float, list[str]]] = {}        # our dns cache
_locks: dict[str, asyncio.Lock] = {}                   # one lock per domain name, so requests
                                                       #   arriving together share a lookup
_active: dict[str, dict] = {}          # hosts being connected to, with the summary each one
                                       #   will print once it goes quiet
_session = {"connections": 0, "denied": 0, "sent": 0, "received": 0, "started": 0.0}

LOG = logging.getLogger("socksscope")

class _Formatter(logging.Formatter):
    def format(self, record):
        mark = f"{record.levelname.lower()}: " if record.levelno != logging.INFO else ""
        return f"{self.formatTime(record, '%H:%M:%S')} {mark}{record.getMessage()}"

def setup_logging(verbose, quiet):
    handler = logging.StreamHandler()
    handler.setFormatter(_Formatter())
    LOG.addHandler(handler)
    LOG.setLevel(logging.WARNING if quiet else logging.DEBUG if verbose else logging.INFO)

def log_event(verb, message, peer=None):
    if peer and LOG.isEnabledFor(logging.DEBUG): message += f" [{peer}]"
    LOG.info(f"{verb:<8}{message}")

def is_ip(s):
    try: ipaddress.ip_address(s)
    except ValueError: return False
    return True


# ── Ruleset ─────────────────────────────────────────────────────────────
# Handle the rules specified at startup and apply them during runtime

class Denied(Exception):
    """Refused by the ruleset"""

class Verdict(enum.IntEnum):
    ALLOW = 0
    BLOCK = 1
    def __str__(self): return self.name.lower()
    def __invert__(self): return Verdict(1 - self)

class Rule:
    def __init__(self, type, value, rank, verdict, text):
        # type is 'name', 'ip' or 'port'
        # rank decides how specific a rule is and only rules of the same
        #   type are compared so the rank does not need to be consistent between types
        self.type, self.value, self.rank, self.verdict = type, value, rank, verdict
        self.text = f"{verdict} {text}"

    def matches(self, candidate):
        if self.type == "ip":
            return candidate.version == self.value.version and candidate in self.value
        if self.type == "port":
            return self.value[0] <= candidate <= self.value[1]
        if self.type == "name":
            name, subdomains_only = self.value
            # '*' leaves no name behind, so it covers every domain name there is
            if not name: return True
            return candidate.endswith("." + name) or (not subdomains_only and candidate == name)
        raise RuntimeError(f"{self.type} not as expected")

    def __str__(self):
        return self.text

def parse_port_rule(text, verdict):
    # ':443' or ':8000-8100', both ends included
    low, _, high = text[1:].partition("-")
    low, high = int(low), int(high or low)
    if not 0 < low <= high <= 65535:
        raise ValueError(f"'{text}' is not a port range from low to high within 1-65535")
    # rank: how few ports it covers, so :445 outranks :1-1024
    return [Rule("port", (low, high), -(high - low + 1), verdict, text)]

def parse_ip_rule(text, verdict, label=None):
    # '10.0.0.5', '10.0.0.0/8' or a '10.0.0.1-10.0.0.50' range, both ends included
    if "-" in text:
        first, last = (ipaddress.ip_address(part) for part in text.split("-", 1))
        if first.version != last.version:
            raise ValueError(f"'{text}' is a nonsensical range")
        # a range rarely lines up with one prefix, so it becomes several rules
        nets = list(ipaddress.summarize_address_range(first, last))
    else:
        nets = [ipaddress.ip_network(text, strict=False)]
    # rank: how few addresses it covers, counted over the whole range, otherwise
    #   the pieces of one range would outrank each other
    rank = -sum(net.num_addresses for net in nets)
    return [Rule("ip", net, rank, verdict, label or text) for net in nets]

_DNS_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")

def parse_name_rule(text, verdict):
    # 'corp.local', 'sub.corp.local', '*.corp.local' and bare '*'
    #   '--block *' refuses every domain name; '--allow *' is a noop
    if text == "*": return [Rule("name", ("", True), (0, True), verdict, text)]
    is_wildcard = text.startswith("*.")
    name = text.removeprefix("*.").removesuffix(".").lower()
    labels = name.split(".")
    if name and all(label.isdigit() for label in labels):
        LOG.warning(f"'{text}' looks like you intended an IP but it's not valid and parsed as a domain name")
    if not name or len(name) > 253 or not all(_DNS_LABEL.match(label) for label in labels):
        raise ValueError(f"'{text}' is not a domain name we can use for the ruleset")
    # rank: deeper subdomains win so vpn.corp.local outranks corp.local
    return [Rule("name", (name, is_wildcard), (name.count(".") + 1, is_wildcard), verdict, text)]

def parse_rule(text, verdict):
    # pick the type from the shape of the text and let that parser build the rules
    if not text: raise ValueError("empty rule can't be processed")
    # IP ranges and single IPs/Subnets first (IPv6 may look like a Port)
    if "-" in text and all(is_ip(part) for part in text.split("-", 1)):
        return parse_ip_rule(text, verdict)
    try: ipaddress.ip_network(text, strict=False)
    except ValueError: pass
    else: return parse_ip_rule(text, verdict)
    # ':443' and ':1-1024' are ports
    if text.startswith(":"):
        return parse_port_rule(text, verdict)
    if text.isdigit():
        # a bare number is not an address and would silently become a domain name
        raise ValueError(f"'{text}' looks like a port, write it as ':{text}'")
    # Domain name
    return parse_name_rule(text, verdict)

class Ruleset:
    def __init__(self, allow, block):
        # rules directly specified as an argument
        self.rules = self._load(allow, Verdict.ALLOW) + self._load(block, Verdict.BLOCK)
        # rules derived from --resolve-rules, kept per domain name so we can track previous addresses
        self.resolved = {}
        # when each of the --resolve-rules names was last confirmed (for the grace period)
        self._resolved_at = {}
        # all rules that must be honored (self.rules plus self.resolved)
        self.active = []
        # which of 'name', 'ip' and 'port' have an allow rule: up until the first
        #   one of a type, everything of that type is accepted
        self.restricted = set()
        self._index()

    @staticmethod
    def _load(entries, verdict):
        # Each entry is either one rule or '@file'
        rules = []
        for entry in entries or []:
            lines = Path(entry[1:]).read_text().splitlines() if entry.startswith("@") else [entry]
            for line in lines:
                line = line.split("#")[0].strip()
                if line:
                    # '!' flips the rule
                    rules += parse_rule(line.lstrip("!"),
                                        ~verdict if line.startswith("!") else verdict)
        return rules

    def _index(self):
        self.active = self.rules + [rule for rules in self.resolved.values() for rule in rules]
        self.restricted = {rule.type for rule in self.active if rule.verdict is Verdict.ALLOW}

    def resolveable_rules(self):
        # return all domain rules that can be resolved for --resolve-rules (no wildcards)
        return [rule for rule in self.rules if rule.type == "name" and not rule.value[1]]

    def wildcard_rules(self):
        return [rule for rule in self.rules if rule.type == "name" and rule.value[1]]

    def reindex_resolved_name(self, name, rules):
        # replaces only what this domain name contributed, so the names that did
        #   resolve are updated and the ones that failed keep what they had
        self.resolved[name] = rules
        self._resolved_at[name] = time.monotonic()
        self._index()

    def unconfirmed_for(self, name):
        # seconds since this domain name last got an answer of any kind
        return time.monotonic() - self._resolved_at.get(name, time.monotonic())

    _DEFAULT_ALLOWS = {"name": ("*",), "ip": ("0.0.0.0/0", "::/0"), "port": (":1-65535",)}
    def default_allows(self):
        return [text for type, texts in self._DEFAULT_ALLOWS.items()
                if type not in self.restricted for text in texts]

    def check_rules(self, type, candidate):
        # return (allowed, rule) where rule is the most specific rule that allows/blocks the candidate
        best = None
        for rule in self.active:
            if rule.type == type and rule.matches(candidate) and (
                    best is None or (rule.rank, rule.verdict) > (best.rank, best.verdict)):
                best = rule
        if best:
            return best.verdict is Verdict.ALLOW, best
        return type not in self.restricted, None


# ── SOCKS5 ──────────────────────────────────────────────────────────────
# Both directions: client and server at the same time, sharing the address field

class ProxyError(Exception):
    """The upstream proxy answered, but would not open the connection"""

# reply codes (RFC 1928), named for the ones we send
OK, FAILED, NOT_ALLOWED, UNREACHABLE, BAD_COMMAND, BAD_ADDRESS = 0, 1, 2, 4, 7, 8
REPLY_TEXT = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
              4: "host unreachable", 5: "connection refused", 6: "TTL expired",
              7: "command not supported", 8: "address type not supported"}

def pack_address(host):
    # ATYP byte and the address (or domain name) after it
    try: address = ipaddress.ip_address(host)
    except ValueError: return b"\x03" + bytes([len(host)]) + host.encode()
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed

async def read_address(reader, atyp):
    # address following an ATYP byte, or None if we do not know that type or the name will not decode
    if atyp == 1: return str(ipaddress.IPv4Address(await reader.readexactly(4)))
    if atyp == 4: return str(ipaddress.IPv6Address(await reader.readexactly(16)))
    if atyp == 3:
        name = await reader.readexactly((await reader.readexactly(1))[0])
        try: return name.decode()
        except UnicodeDecodeError: return None
    return None

# answering our own clients
async def read_request(reader):
    # request from a client
    _ver, cmd, _rsv, atyp = await reader.readexactly(4)
    host = await read_address(reader, atyp)
    if host is None: return cmd, atyp, None, None
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return cmd, atyp, host, port

async def send_reply(writer, rep):
    # answer to a client, we don't need to specify an IPv4 bound address
    #   because it only matters for BIND and UDP ASSOCIATE
    writer.write(b"\x05" + bytes([rep]) + b"\x00\x01" + b"\x00" * 6)
    await writer.drain()

async def authenticate_client(reader, writer, methods):
    # no authentication required
    if LISTEN_AUTH[0] is None:
        writer.write(b"\x05\x00")
        await writer.drain()
        return True
    # none of the offered methods will do
    if 2 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        return False
    # authenticate
    writer.write(b"\x05\x02")
    await writer.drain()

    version, length = await reader.readexactly(2)
    user = await reader.readexactly(length)
    (length,) = await reader.readexactly(1)
    password = await reader.readexactly(length)
    ok = (version == 1 and hmac.compare_digest(user, LISTEN_AUTH[0])
          and hmac.compare_digest(password, LISTEN_AUTH[1]))
    writer.write(b"\x01" + (b"\x00" if ok else b"\x01"))
    await writer.drain()
    return ok

async def read_handshake(reader, writer, peer):
    # everything a client has to send before we act:
    #   greeting, (optional) authentication, a request
    ver, nmethods = await reader.readexactly(2)
    if ver != 5: return None
    methods = await reader.readexactly(nmethods)
    if not await authenticate_client(reader, writer, methods):
        log_event("refused", f"{peer} (--listen-auth credentials missing or wrong)")
        return None
    return await read_request(reader)

# asking the upstream SOCKS5 server
async def authenticate_upstream(reader, writer):
    # Username/password (RFC 1929) to a server
    user, password = UPSTREAM_AUTH[0].encode(), UPSTREAM_AUTH[1].encode()
    writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
    await writer.drain()
    _version, status = await reader.readexactly(2)
    if status != 0:
        raise ProxyError("upstream rejected the credentials")

async def connect_upstream(host, port):
    # Connect to a socks5 server
    reader, writer = await asyncio.open_connection(*UPSTREAM)
    # only the handshake below decides this, and every way out of it that is not
    #   a finished handshake has to close the socket - a cancellation (our own
    #   connect_out() timeout) included, so this is not an 'except Exception'
    connected = False
    try:
        # Greeting
        methods = b"\x00\x02" if UPSTREAM_AUTH[0] is not None else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()
        _version, method = await reader.readexactly(2)
        # Authentication (if we are asked for one)
        if method == 2: await authenticate_upstream(reader, writer)
        elif method != 0:
            raise ProxyError("upstream accepted none of the authentication methods we offered"
                             if method == 0xFF else f"upstream asked for method {method}")
        # Connect
        writer.write(b"\x05\x01\x00" + pack_address(host) + struct.pack("!H", port))
        await writer.drain()
        _version, rep, _rsv, atyp = await reader.readexactly(4)
        if rep != OK:
            raise ProxyError(f"upstream said {REPLY_TEXT.get(rep, rep)}")
        # Handle response (drop it)
        if await read_address(reader, atyp) is None:
            raise ProxyError(f"upstream replied with address type {atyp}")
        await reader.readexactly(2)
        connected = True
        return reader, writer
    except asyncio.IncompleteReadError:
        raise ProxyError("upstream closed the connection without replying") from None
    finally:
        # Ensure that we always close even when the connection was not established correctly
        if not connected: writer.close()

async def connect_out(host, port, local=False):
    # Open a connection to the target, through the upstream or local
    if local or UPSTREAM is None: opening = asyncio.open_connection(host, port)
    else: opening = connect_upstream(host, port)
    try: return await asyncio.wait_for(opening, CONNECT_TIMEOUT)
    # re-raise TimeoutError to give it a meaningful message
    except asyncio.TimeoutError: raise TimeoutError(f"no answer within {CONNECT_TIMEOUT}s") from None


# ── Name resolution ─────────────────────────────────────────────────────
# Resolve domain names using the way specified on the commandline

class DNSError(Exception):
    """The DNS server answered, but not with anything usable"""

class NXDomain(DNSError):
    """The server said this domain name does not exist anywhere, so there is
    no point asking it anything else about that domain name"""

def parse_host_entry(line):
    # 'name=ADDRESS' or the /etc/hosts form 'ADDRESS name [name ...]'
    if "=" in line:
        name, _, address = line.partition("=")
        address, names = address.strip(), [name.strip()]
    else:
        address, *names = line.split()
    if not is_ip(address) or not names or not all(names):
        raise ValueError(f"'{line}' is neither 'name=ADDRESS' nor 'ADDRESS name [name ...]'")
    return address, names

def load_hosts(entries):
    # Each entry is either one mapping or '@file'
    for entry in entries or []:
        lines = Path(entry[1:]).read_text().splitlines() if entry.startswith("@") else [entry]
        for line in lines:
            line = line.split("#")[0].strip()
            if line:
                address, names = parse_host_entry(line)
                for name in names:
                    HOSTS.setdefault(name.lower(), []).append(address)

async def query(host, rdtype):
    # one DNS query for one record type and return (addresses, ttl)
    request = dns.message.make_query(host, rdtype)
    if DNS_TRANSPORT == "udp":
        reply = await dns.asyncquery.udp(request, DNS_SERVER[0], port=DNS_SERVER[1], timeout=CONNECT_TIMEOUT)
    else:
        # Handle DNS/TCP by hand to use our connection logic
        wire = request.to_wire()
        reader, writer = await connect_out(*DNS_SERVER, local=DNS_SIDE == "local")
        try:
            # send two byte length prefix + the query and receive the same as a response
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            reply = dns.message.from_wire(await reader.readexactly(length))
        finally:
            writer.close()

    # Reject anything unusable
    if not request.is_response(reply):
        raise DNSError("reply does not match the query")
    if reply.rcode() == dns.rcode.NXDOMAIN:
        raise NXDomain(host)
    if reply.rcode() != dns.rcode.NOERROR:
        raise DNSError(f"server said {dns.rcode.to_text(reply.rcode())}")

    # Follow any CNAME chain to the address records
    chain = reply.resolve_chaining()
    if chain.answer is None:
        return [], chain.minimum_ttl
    return [rdata.address for rdata in chain.answer], chain.minimum_ttl

async def resolve_dns(host):
    # Cached A and AAAA lookup, returns (addresses, came from cache)
    # Start with shortcut for cached entries
    hit = _cache.get(host)
    if hit and hit[0] > time.time():
        return hit[1], True

    lock = _locks.setdefault(host, asyncio.Lock())
    # One lookup per domain name at a time to prevent sending multiple queries
    #   by checking the cache first
    async with lock:
        hit = _cache.get(host)
        if hit and hit[0] > time.time():
            return hit[1], True
        # Ask A and AAAA at the same time
        answers = await asyncio.gather(query(host, dns.rdatatype.A),
                                       query(host, dns.rdatatype.AAAA),
                                       return_exceptions=True)
        addresses, ttls, failure = [], [], None
        for answer in answers:
            if isinstance(answer, NXDomain): continue
            if isinstance(answer, BaseException): failure = failure or answer
            else:
                found, found_ttl = answer
                addresses += found
                if found: ttls.append(found_ttl)
        # only raise on error if A and AAAA returned nothing
        if not addresses and failure is not None: raise failure
        # cache the addresses or cache the miss
        ttl = max(TTL_MIN, min(min(ttls), TTL_MAX)) if addresses else NEG_TTL
        _cache[host] = (time.time() + ttl, addresses)
        return addresses, False

async def resolve_system(host):
    # whatever the local machine itself would resolve (/etc/hosts and resolv.conf honored)
    info = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    # getaddrinfo answers once per socket type and protocol
    #   dict.fromkeys drops the repeats while keeping returned order
    return list(dict.fromkeys(sockaddr[0] for *_, sockaddr in info))

async def resolve_target(host):
    host = host.lower()
    # Choose which resolver should be used
    if host in HOSTS: addresses, source = HOSTS[host], "--hosts"
    elif DNS_SERVER:
        addresses, cached = await resolve_dns(host)
        source = f"{'cached - ' if cached else ''}{DNS_SERVER[0]}:{DNS_SERVER[1]}"
    elif DNS_SIDE == "local": addresses, source = await resolve_system(host), "system resolver"
    # None of the above means we let the upstream handle it
    else: return None
    LOG.debug(f"resolved {host} -> {head_elements(addresses, 4) or 'nothing'} ({source})")
    return addresses


# ── Traffic limits ──────────────────────────────────────────────────────
# Restrict speed and maximum connections

class TokenBucket:
    # Handle rate limiting for --rate and --rate-per-conn
    def __init__(self, rate):
        # tokens are bytes and rate is bytes per second so the bucket holds
        #   one second of traffic (that much may burst before it starts pacing)
        self.rate, self.tokens, self.stamp = rate, rate, time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self, amount):
        async with self.lock:
            # refill for the time that passed rather than on a timer
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.stamp) * self.rate)
            self.stamp = now
            # take the requested amount, going negative if it is not there yet
            self.tokens -= amount
            if self.tokens < 0:
                # if too much is taken sleep until enough time has passed to
                #   accommodate them
                # intentionally sleeping while holding the lock, which keeps
                #   waiting connections in order instead of racing for tokens
                #   the longest sleep is 8192/rate (see pipe())
                await asyncio.sleep(-self.tokens / self.rate)

@contextlib.asynccontextmanager
async def slot(peer):
    # Handle --max-conns slots
    # asynccontextmanager makes this usable with 'async with'
    if _SLOTS is None: yield; return
    if _SLOTS.locked(): LOG.debug(f"{peer} waiting for a free slot")
    await asyncio.wait_for(_SLOTS.acquire(), QUEUE_TIMEOUT or None)
    try: yield
    # always release the slot no matter how we exit here
    finally: _SLOTS.release()


# ── Connections ─────────────────────────────────────────────────────────
# Combine everything above to handle the connections

async def approved_targets(peer, host, atyp, port):
    # Ports first: judging one needs no lookup and no connection
    allowed, rule = _RULESET.check_rules("port", port)
    if not allowed: raise Denied(rule or "port not allowed by ruleset")

    # Clients may put an IP literal in a DOMAIN-type request and looking those
    #   up would NXDOMAIN, so treat them as what they are
    if atyp != 3 or is_ip(host):
        allowed, rule = _RULESET.check_rules("ip", ipaddress.ip_address(host))
        if not allowed: raise Denied(rule or "address not allowed by ruleset")
        return [host]

    # Apply the domain name rules and resolve it to an IP
    allowed, rule = _RULESET.check_rules("name", host.lower())
    if not allowed: raise Denied(rule or "domain name not allowed by ruleset")
    addresses = await asyncio.wait_for(resolve_target(host), CONNECT_TIMEOUT)
    if addresses is None: return [host]
    if not addresses: raise DNSError("no A or AAAA record")

    # resolving may return several IPs which we all need to check because
    #   we don't know which one will be chosen afterwards (in handle())
    kept, dropped = [], []
    for address in addresses:
        allowed, rule = _RULESET.check_rules("ip", ipaddress.ip_address(address))
        if allowed: kept.append(address)
        else: dropped.append(f"{address} ({rule or 'not allowed by ruleset'})")
    if dropped: log_event("dropped", f"{host}: {head_elements(dropped, 3, ', ')}", peer)
    if not kept: raise Denied(f"all {len(addresses)} resolved addresses not allowed by ruleset")
    return kept

_ENDED = {ConnectionResetError: "reset", BrokenPipeError: "broken pipe",
          ConnectionAbortedError: "aborted", TimeoutError: "timed out"}

def ended_reason_summary(error):
    if error is None: return None
    return _ENDED.get(type(error)) or f"{type(error).__name__}{f': {error}' if str(error) else ''}"

def closing_summary(client_to_target, target_to_client):
    (sent, sending_error), (received, receiving_error) = client_to_target, target_to_client
    counts = f"sent {human(sent)}, received {human(received)}"
    sending_reason = ended_reason_summary(sending_error)
    receiving_reason = ended_reason_summary(receiving_error)

    if sending_reason is None and receiving_reason is None: return counts
    if sending_reason == receiving_reason: return f"{counts} - {sending_reason}"
    if receiving_reason is None: return f"{counts} - {sending_reason} while sending"
    if sending_reason is None: return f"{counts} - {receiving_reason} while receiving"
    return f"{counts} - {sending_reason} while sending; {receiving_reason} while receiving"

def host_entry(host):
    # what a host has been up to since it was last summarised
    return _active.setdefault(host, {
        "connections": 0, "ports": {}, "sent": 0, "received": 0, "live": 0, "denied": 0,
        "denied_ports": {}, "reasons": {}, "announced": set(), "last_seen": time.monotonic()})

def record_connection(host, port, target):
    entry = host_entry(host)
    if ("connect", port, target) not in entry["announced"]:
        entry["announced"].add(("connect", port, target))
        log_event("connect", f"{host}:{port}" + (f" -> {target}" if target != host else ""))
    entry["connections"] += 1
    entry["ports"][port] = None
    entry["live"] += 1
    entry["last_seen"] = time.monotonic()
    _session["connections"] += 1

def record_denial(host, port, reason, peer):
    entry = host_entry(host)
    if ("denied", port, reason) not in entry["announced"]:
        entry["announced"].add(("denied", port, reason))
        log_event("denied", f"{host}:{port} ({reason})", peer)
    entry["denied"] += 1
    entry["denied_ports"][port] = None
    entry["reasons"][reason] = None
    entry["last_seen"] = time.monotonic()
    _session["denied"] += 1

def record_close(host, sides):
    (sent, _), (received, _) = sides
    entry = _active[host]
    entry["sent"] += sent
    entry["received"] += received
    entry["live"] -= 1
    entry["last_seen"] = time.monotonic()
    _session["sent"] += sent
    _session["received"] += received

def summarise_host(host):
    entry = _active.pop(host)
    made, refused, parts = entry["connections"], entry["denied"], []
    if made:
        ports = head_elements([f":{port}" for port in entry["ports"]], 4, ", ")
        parts.append(f"{made} connection{'' if made == 1 else 's'} on {ports}")
    if refused:
        ports = head_elements([f":{port}" for port in entry["denied_ports"]], 4, ", ")
        parts.append(f"{refused} denied on {ports} ({head_elements(list(entry['reasons']), 2, '; ')})")
    counts = f" - sent {human(entry['sent'])}, received {human(entry['received'])}" if made else ""
    log_event("summary", f"{host}: {', '.join(parts)}{counts}")

async def summarise_quiet_hosts():
    while True:
        await asyncio.sleep(1)
        now = time.monotonic()
        for host in [host for host, entry in _active.items()
                     if not entry["live"] and now - entry["last_seen"] > HOST_QUIET]:
            summarise_host(host)

def summarise_session():
    for host in list(_active): summarise_host(host)
    seconds = int(time.monotonic() - _session["started"])
    spent = f"{seconds // 60}m{seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"
    LOG.info("=====================")
    made = _session["connections"]
    log_event("session", f"{spent}: {made} connection{'' if made == 1 else 's'},"
              f" {_session['denied']} denied"
              f" - sent {human(_session['sent'])}, received {human(_session['received'])}")

async def pipe(reader, writer, buckets):
    # Shovel bytes one way until EOF, then half-close so the peer sees the end
    # Smaller read sizes keep a throttled stream smooth
    # Returns (bytes moved, what ended it)
    size = 8192 if buckets else 65536
    moved, ended = 0, None
    try:
        while chunk := await reader.read(size):
            for bucket in buckets:
                await bucket.take(len(chunk))
            writer.write(chunk)
            await writer.drain()
            moved += len(chunk)
    except Exception as e: ended = e
    finally:
        # the peer may already be gone, in which case there is no one to tell
        try: writer.write_eof()
        except Exception: pass
    return moved, ended

async def handle(client_reader, client_writer):
    peer = "%s:%s" % (client_writer.get_extra_info("peername") or ("?", "?"))[:2]
    target_writer = None
    # hold a reference to the task of a connection to ensure our cleanup runs even
    #   when both ends of the connection are gone (prevent it from being terminated
    #   by the garbage collector because asyncio only holds a weak reference and
    #   the stream protocol drops it in connection_lost())
    task = asyncio.current_task()
    _running.add(task)
    try:
        request = await asyncio.wait_for(
            read_handshake(client_reader, client_writer, peer), HANDSHAKE_TIMEOUT)
        if request is None: return

        # Judge the request; refuse unknown address types (0x08) and any
        #   command other than CONNECT (0x07)
        cmd, atyp, host, port = request
        if host is None: return await send_reply(client_writer, BAD_ADDRESS)
        if cmd != 1: return await send_reply(client_writer, BAD_COMMAND)
        if not 0 < port <= 65535: return await send_reply(client_writer, FAILED)

        # Apply the ruleset and resolve, 0x02 is "not allowed by ruleset" and
        #   0x04 "host unreachable" for a lookup that genuinely failed
        try: targets = await approved_targets(peer, host, atyp, port)
        except Denied as denial:
            record_denial(host, port, str(denial), peer)
            return await send_reply(client_writer, NOT_ALLOWED)
        except Exception as e:
            log_event("resolve", f"{host} failed: {e or type(e).__name__}", peer)
            return await send_reply(client_writer, UNREACHABLE)

        try:
            async with slot(peer):
                # Try each address in turn and the first to connect wins
                # Only if every one fails do we return a general failure (0x01)
                failures = []
                for target in targets:
                    try:
                        target_reader, target_writer = await connect_out(target, port)
                        break
                    except Exception as e:
                        failures.append(f"{target} ({e or type(e).__name__})"
                                        if len(targets) > 1 else f"{e or type(e).__name__}")
                        LOG.debug(f"{peer} connect {target}:{port} failed: {e or type(e).__name__}")
                else:
                    log_event("failed", f"{host}:{port} - {head_elements(failures, 3, ', ')}", peer)
                    return await send_reply(client_writer, FAILED)
                LOG.debug(f"{peer} {host}:{port} -> {target}")
                record_connection(host, port, target)

                # Both directions share the buckets, so a rate is the total for
                #   the connection rather than per direction
                buckets = [b for b in (_RATE, RATE_PER_CONN and TokenBucket(RATE_PER_CONN)) if b]
                await send_reply(client_writer, OK)
                started = time.monotonic()
                to_target = asyncio.create_task(pipe(client_reader, target_writer, buckets))
                to_client = asyncio.create_task(pipe(target_reader, client_writer, buckets))
                # waits for the first EOF, so a connection where neither side ever sends one is
                #   never timed out here and keeps its --max-conns slot
                #   decided against a timeout and TCP keepalives because the tools/clients should
                #   handle those cases themselves
                await asyncio.wait((to_target, to_client), return_when=asyncio.FIRST_COMPLETED)
                # Connections where only one side is closed should get a chance to finish before we time them out
                one_sided = [side for side in (to_target, to_client) if not side.done()]
                if one_sided:
                    _, still_running = await asyncio.wait(one_sided, timeout=HALF_OPEN_TIMEOUT)
                    if still_running:
                        log_event("closed", f"{host}:{port} after the other direction ended {HALF_OPEN_TIMEOUT}s ago", peer)
                        # closing instead of cancelling, to keep the byte counts
                        target_writer.close()
                        client_writer.close()
                sides = await asyncio.gather(to_target, to_client, return_exceptions=True)
                record_close(host, sides)
                LOG.debug(f"{peer} {host}:{port} closed after {time.monotonic() - started:.1f}s, {closing_summary(*sides)}")
        except asyncio.TimeoutError:
            log_event("timeout", f"{host}:{port} gave up waiting for a slot", peer)
            return await send_reply(client_writer, FAILED)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except asyncio.TimeoutError:
        # only the handshake should reach here, the slot wait is caught above
        LOG.debug(f"{peer} gave up on the handshake after {HANDSHAKE_TIMEOUT}s")
    except Exception as e:
        # Log if a connection to our listener is closed unexpectedly (e.g. the peer sends garbage)
        LOG.debug(f"{peer} dropped: {e or type(e).__name__}")
    finally:
        if target_writer is not None: target_writer.close()
        client_writer.close()
        _running.discard(task)


# ── Resolved rules ──────────────────────────────────────────────────────
# Handle --resolve-rules which is ruleset and DNS at once

async def resolve_rules(startup=False):
    # resolve the domain names from the arguments to IPs
    unreachable, gone = [], []
    for rule in _RULESET.resolveable_rules():
        name = rule.value[0]
        # resolve without the cache, so TTL_MIN cannot silently cap how fast
        #   --resolve-rules-every reacts to a changed answer
        _cache.pop(name, None)
        try:
            addresses = await resolve_target(name) or []
        except Exception as e:
            unreachable.append((name, f"{name} ({e})"))
            continue
        if not addresses:
            # the server did answer but we have no address at the moment
            gone.append(name)
        resolved = []
        for address in addresses:
            resolved += parse_ip_rule(address, rule.verdict, f"{address} (from {name})")
        _RULESET.reindex_resolved_name(name, resolved)

    if startup:
        # Fail at startup to prevent typos and unintended rules
        if unreachable or gone:
            raise DNSError("could not resolve " + ", ".join(
                [text for _, text in unreachable] + [f"{n} (no address record)" for n in gone]))
    else:
        # Allow a grace period at runtime so a single lost packet or a restarting
        #   DNS server does not take the tunnel down
        # We want to fail however if rules can not be verified anymore
        grace = 3 * RESOLVE_RULES_EVERY
        expired = [text for name, text in unreachable
                   if _RULESET.unconfirmed_for(name) > grace]
        if expired:
            raise DNSError("could not re-resolve " + ", ".join(expired) + " for over "
                           f"{grace}s - their IP rules cannot be verified, so stopping")
        if unreachable:
            LOG.warning(f"could not re-resolve {', '.join(t for _, t in unreachable)}"
                        f" - keeping their previous addresses, stopping if they are still "
                        f"unconfirmed after {grace}s")
        if gone:
            LOG.info(f"note: {', '.join(gone)} no longer resolve, their address rules are dropped")

    global _resolved_log
    resolved = [rule for rules in _RULESET.resolved.values() for rule in rules]
    summary = f"{len(_RULESET.resolveable_rules())} domain name rule(s) resolved into {len(resolved)}"
    if resolved: summary += f": {head_elements(resolved, 4, ', ')}"
    changed, _resolved_log = summary != _resolved_log, summary
    LOG.log(logging.INFO if startup or changed else logging.DEBUG, summary)

async def refresh_rules():
    # Regularly refresh the resolved rules
    while True:
        await asyncio.sleep(RESOLVE_RULES_EVERY)
        await resolve_rules()


# ── Arguments ───────────────────────────────────────────────────────────

def parse_hostport(s, default_port, default_host=None):
    # Parse ipv4 and ipv6 host[:port] combinations
    def parse_port(text):
        if not text.isdigit() or not 0 < int(text) <= 65535:
            raise ValueError(f"'{text}' is not a port from 1 to 65535")
        return int(text)

    # Handle obvious single IP cases
    if is_ip(s): return (s, default_port)
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return (host, parse_port(rest[1:]) if rest.startswith(":") else default_port)
    host, sep, port = s.rpartition(":")
    if not sep:
        # Single values we treat as a port if we have a default host
        if default_host and s.isdigit():
            return (default_host, parse_port(s))
        return (s, default_port)
    # The easy explicit case (we got ip:port or :port)
    return (host or default_host or "", parse_port(port))

_DNS_SIDES = {"u": "upstream", "upstream": "upstream", "l": "local", "local": "local"}

def parse_dns(text):
    # Parse our dns grammar [u|upstream|l|local][:SERVER[:PORT][:tcp|:udp]]
    side, _, rest = text.partition(":")
    side = side.lower()
    if side not in _DNS_SIDES:
        raise argparse.ArgumentTypeError(f"'{text}' is not a valid --dns argument - check "
                                         "out --help on how to specify it!")
    side = _DNS_SIDES[side]
    if not rest: return side, None, None

    server, _, transport = rest.rpartition(":")
    transport = transport.lower()
    if transport in ("tcp", "udp"): rest = server
    else: transport = "tcp" if side == "upstream" else "udp"
    if not rest:
        raise argparse.ArgumentTypeError(f"'{text}' names no DNS server")
    if side == "upstream" and transport == "udp":
        raise argparse.ArgumentTypeError("upstream with udp DNS does not work - check "
                                         "out --help and the README on Github for explanations!")
    try: address, port = parse_hostport(rest, 53)
    except ValueError as e: raise argparse.ArgumentTypeError(
        f"'{rest}' is not a SERVER[:PORT]: {e}") from None
    # a domain name here would need a resolver before we have one
    if not is_ip(address):
        raise argparse.ArgumentTypeError(
            f"'{address}' is not an IP address - resolve it yourself first if it is a domain name!")
    return side, (address, port), transport

def size(text):
    # Convert human readable sizes to numbers
    factor = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}.get(text[-1:].lower(), 1)
    try: number = float(text.rstrip("kmgKMG"))
    except ValueError: number = -1
    if number < 0:
        raise argparse.ArgumentTypeError(f"'{text}' is not a size like 1M, 512k or 4096")
    if int(number * factor) < 1:
        raise argparse.ArgumentTypeError(f"'{text}' is not a rate anything can flow at")
    return int(number * factor)

def human(count):
    # Convert numbers to human readable sizes
    for unit, factor in (("G", 1024 ** 3), ("M", 1024 ** 2), ("k", 1024)):
        if count >= factor: return f"{count / factor:.1f}{unit}"
    return f"{count}B"

def head_elements(items, limit, sep=" "):
    items = [str(item) for item in items]
    if len(items) <= limit or LOG.isEnabledFor(logging.DEBUG): return sep.join(items)
    return sep.join(items[:limit]) + f"{sep}+{len(items) - limit} more"

_description = """\
socksscope - a SOCKS5 front-end that lets you manage your traffic and keep it
inside your engagement scope. Can wrap an existing SOCKS5 port (--upstream)
or act independently (--local).

Every CONNECT is judged against a ruleset of domain names, addresses and ports,
given as arguments or in files at startup. Additionally you can specify a DNS
server to use and throttle connection speeds.

While it's possible to use socksscope securely, this is a pentesting/redteaming
tool and NOT a privacy tool. There are a lot of ways to misconfigure socksscope!
"""

_description_rules_dns_warn = """\
Watch out for unexpected rulesets when combining IP address and domain name rules.
(Check the README on Github for more information!)
"""

_epilog_short = """\
Run '%(prog)s --help' for the full help!
"""

_epilog_full = """\
For more detailed examples, reasonings behind design decisions as well as an in-depth
explanation of socksscope's DNS resolving (especially when wrapping a SOCKS5 port and
actively resolving domain name rules using --resolve-rules) check the README on Github.

examples:
  %(prog)s -u 1080 --dns u:10.0.0.53 --allow @scope.txt
  %(prog)s -u 1080 --resolve-rules --allow 'intranet.corp.local' --allow :443
  %(prog)s --local --allow 10.0.0.0/8 --rate 1M --max-conns 20
  %(prog)s --allow @scope.txt --test-ruleset admin.corp.local:445
"""

def build_parser(full=False):
    # Help got too long so splitting it into '-h' and '--help'
    def help_text(short_help=None, long_help=""):
        if full: return (f"{short_help} " if short_help else "") + long_help
        else: return short_help if short_help else argparse.SUPPRESS

    p = argparse.ArgumentParser(
        add_help=False,
        description=_description + _description_rules_dns_warn,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog_full if full else _epilog_short)

    p.add_argument("-h", action="help",
                   help="show a short help message and exit")
    p.add_argument("--help", action="help",
                   help="show the full help and exit")
    p.add_argument("-l", "--listen", metavar="[HOST:]PORT",
                   help=help_text(short_help=f"SOCKS5 port %(prog)s opens (default: {LISTEN[0]}:{LISTEN[1]})",
                                  long_help="- (restricted) SOCKS5 port where the client programs connect to"))
    p.add_argument("--listen-auth", metavar="USER:PASS",
                   help=help_text(long_help="optional credentials for the SOCKS5 port socksscope opens"))
    p.add_argument("--local", action="store_true",
                   help=help_text(short_help="no SOCKS5 proxy to wrap, run %(prog)s independently",
                                  long_help="- connect out from this host while enforcing the ruleset"))
    p.add_argument("-u", "--upstream", metavar="[HOST:]PORT",
                   help=f"the existing SOCKS5 proxy that will be wrapped (default: {UPSTREAM[0]}:{UPSTREAM[1]})")
    p.add_argument("--upstream-auth", metavar="USER:PASS",
                   help=help_text(long_help="optional credentials for the upstream proxy"))
    p.add_argument("-v", "--verbose", action="store_true",
                   help=help_text(long_help="log every connection with additional information"))
    p.add_argument("-q", "--quiet", action="store_true",
                   help=help_text(long_help="log warnings only"))
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}",
                   help=help_text(long_help="show the version and exit"))

    ruleset = p.add_argument_group("ruleset")
    ruleset.add_argument("--allow", action="append", metavar="RULE",
                        help=help_text(short_help="domain name, IP address or port rule to allow (repeatable)",
                                       long_help="- Rules: domain.tld | *.domain.tld | * | IP | IP/NET | "
                                                 "IP-IP | :PORT | :PORT-PORT - @FILE loads a "
                                                 "rules file - ranges include both ends "
                                                 "- '!' inverts a rule"))
    ruleset.add_argument("--block", action="append", metavar="RULE",
                        help=help_text(short_help="same as --allow but blocked instead (repeatable)",
                                       long_help="- syntax exactly like --allow"))
    ruleset.add_argument("--test-ruleset", action="append", metavar="HOST[:PORT]",
                        help=help_text(short_help="print how a target would be judged, then exit (repeatable)",
                                       long_help="- a target without a PORT is judged as :80"))
    ruleset.add_argument("--resolve-rules", action="store_true",
                        help="resolve domain name rules and apply them as IP address rules (results in repeating queries)")
    ruleset.add_argument("--yes-resolve-rules", action="store_true",
                        help=help_text(long_help="answer the startup --resolve-rules confirmation with yes"))
    ruleset.add_argument("--resolve-rules-every", type=int, metavar="SEC",
                        help=help_text(long_help="interval to re-resolve domain name rules (see --resolve-rules) - if a "
                                                 "domain name rule is unconfirmed for three intervals socksscope exits - "
                                                 f"use 0 to resolve only once at startup (default: {RESOLVE_RULES_EVERY})"))

    dns_group = p.add_argument_group("DNS")
    dns_group.add_argument("--dns", type=parse_dns, metavar="SIDE[:SERVER[:PORT][:tcp|udp]]",
                           help=help_text(short_help="specify where DNS queries should be resolved and what protocol to use",
                                          long_help="- check the README on Github for explanations of all combinations "
                                                    "- SIDE=[u|upstream] to resolve through the wrapped SOCKS5 "
                                                    "- SIDE=[l|local] to resolve via the host socksscope is running on "
                                                    "- [:SERVER[:PORT]] optionally specify a DNS server "
                                                    "- [:tcp|:udp] optionally specify the DNS transport protocol"))
    dns_group.add_argument("--hosts", action="append", metavar="ENTRY",
                           help=help_text(short_help="static mapping used before any DNS (like /etc/hosts) (repeatable)",
                                          long_help="- 'name=ADDRESS' or 'ADDRESS name' or '@FILE' to load a list"))

    limits = p.add_argument_group("limits")
    limits.add_argument("--rate", type=size, metavar="SIZE",
                        help=help_text(short_help="total bytes/s over all connections",
                                       long_help="(e.g. 1M, 512k)"))
    limits.add_argument("--rate-per-conn", type=size, default=0, metavar="SIZE",
                        help=help_text(long_help="bytes/s for a single connection"))
    limits.add_argument("--max-conns", type=int, metavar="N",
                        help=help_text(short_help="connections to run at once",
                                       long_help="- the rest queue instead of failing"))
    limits.add_argument("--queue-timeout", type=int, metavar="SEC",
                        help=help_text(long_help="give up queueing after this long, 0 waits "
                                                 f"forever (default: {QUEUE_TIMEOUT})"))
    return p


# ── Startup ─────────────────────────────────────────────────────────────

def resolver_string():
    if not DNS_SERVER: return "the system resolver"
    return (f"{DNS_SERVER[0]}:{DNS_SERVER[1]} over {DNS_TRANSPORT.upper()}"
            + (" through the upstream" if DNS_SIDE == "upstream" else ""))

def confirm_rule_resolving(parser, assume_yes, test=False):
    # prompt the user before sending the first queries when using --resolve-rules
    names = sorted({rule.value[0] for rule in _RULESET.resolveable_rules()})
    skipped = _RULESET.wildcard_rules()
    if skipped:
        print(f"warning: {len(skipped)} wildcard rule(s) cannot be resolved and stay "
              f"name-only: {', '.join(str(rule) for rule in skipped)}", file=sys.stderr)
    if not names:
        parser.error("--resolve-rules needs at least one domain name rule that is not a wildcard")

    # statically mapped hosts are not answered via network anyway so skip them
    asked = [name for name in names if name not in HOSTS]
    if not asked: return True

    if test: when = "This is done once at startup, only to answer --test-ruleset."
    elif RESOLVE_RULES_EVERY:
        when = (f"They are re-resolved every {RESOLVE_RULES_EVERY} seconds, and one still "
                f"unconfirmed after {3 * RESOLVE_RULES_EVERY} seconds stops the tool.")
    else: when = "They are resolved once, at startup."
    print(f"\n\n--resolve-rules will actively query {resolver_string()} for {len(asked)} name(s):\n"
          f"  {', '.join(asked)}\n"
          "Their resolved addresses will be applied as IP rules! " + when, file=sys.stderr)

    if assume_yes: return True
    if not sys.stdin.isatty():
        if test: return False
        parser.error("--resolve-rules wants a confirmation and there is no terminal to ask; "
                     "pass --yes-resolve-rules if you meant it")
    return input("Send these queries now? [y/N] ").strip().lower() in ("y", "yes")

def confirm_test_queries_resolving(targets, has_ip_rules):
    names = sorted({name for name in (parse_hostport(t, None)[0].lower() for t in targets)
                    if not is_ip(name) and name not in HOSTS})
    if (not names or (DNS_SIDE == "upstream" and DNS_SERVER is None) or not has_ip_rules):
        return False
    print(f"\n\n--test-ruleset will actively query {resolver_string()} for {len(names)} name(s):\n"
          f"  {', '.join(names)}\n"
          "so they can be judged against the IP rules, the way a real run does.", file=sys.stderr)
    return sys.stdin.isatty() and input("Send these queries now? [y/N] ").strip().lower() in ("y", "yes")

async def test_ruleset(targets, resolved=False):
    global DNS_SIDE, DNS_SERVER
    has_ip_rules = any(rule.type == "ip" for rule in _RULESET.active)
    why_unresolved = ("the upstream resolves it, so socksscope never sees its address"
                      if DNS_SIDE == "upstream" and DNS_SERVER is None else "you chose not to resolve the name here")
    if not confirm_test_queries_resolving(targets, has_ip_rules):
        # misuse "upstream" resolving for this case because it already resolves nothing
        DNS_SIDE, DNS_SERVER = "upstream", None
    if RESOLVE_RULES and not resolved:
        print("\n\nnote: you chose not to resolve the domain name rules, so some address rules "
              "might be missing from the test ruleset\n", file=sys.stderr)
    print("=====================\n")
    denied = 0
    for target in targets:
        host, port = parse_hostport(target, None)
        if port is None:
            port, target = 80, f"[{host}]:80" if ":" in host else f"{host}:80"
        try:
            reached = await approved_targets("--test-ruleset", host, 1 if is_ip(host) else 3, port)
            print(f"{target:34} => ALLOW -> {head_elements(reached, 4)}")
            # nothing was substituted for the name, so no address was ever judged
            if has_ip_rules and not is_ip(host) and reached == [host]:
                print(f"  (not judged against the IP rules: {why_unresolved})")
        except Denied as denial:
            print(f"{target:34} => DENY  ({denial})")
            denied += 1
        except Exception as e:
            print(f"{target:34} => UNREACHABLE ({e or type(e).__name__})")
            denied += 1
    return 1 if denied else 0

async def serve():
    if RESOLVE_RULES:
        # fails if a rule can't be resolved because we don't want silently missing rules
        await resolve_rules(startup=True)

    server = await asyncio.start_server(handle, *LISTEN)
    # always name the resolver, it decides how much the IP rules get to see
    resolver = (f"{DNS_SERVER[0]}:{DNS_SERVER[1]}/{DNS_TRANSPORT} ({DNS_SIDE})" if DNS_SERVER else DNS_SIDE)
    LOG.info(f"listening on {LISTEN[0]}:{LISTEN[1]} -> "
           + ("local" if UPSTREAM is None else f"socks {UPSTREAM[0]}:{UPSTREAM[1]}")
           + f", dns {resolver}{', authenticated' if LISTEN_AUTH[0] is not None else ''}")
    # Print the complete ruleset (including defaults) at startup
    for text in _RULESET.default_allows(): LOG.info(f"  rule allow {text} (default)")
    # deduplicated by text: a range is several rules internally but one to read
    for text in dict.fromkeys(str(rule) for rule in _RULESET.active): LOG.info(f"  rule {text}")
    if not _RULESET.active: LOG.info("  no ruleset defined, everything is allowed")
    LOG.info("")
    LOG.info("repeated connections to a host are counted, not logged")
    LOG.info(f"each host is summarised and reset {HOST_QUIET}s after it goes quiet")
    LOG.info("=====================\n")

    # Server is running since start_server() so we idle here until cancelled
    #   Not serve_forever() which waits for live connections to close on cancellation
    until_cancelled = asyncio.Event()
    _session["started"] = time.monotonic()
    # gathered so errors in the background tasks are handled here
    tasks = [until_cancelled.wait(), summarise_quiet_hosts()]
    if RESOLVE_RULES and RESOLVE_RULES_EVERY: tasks.append(refresh_rules())
    try: await asyncio.gather(*tasks)
    finally:
        # stop accepting; asyncio.run() cancels the handlers still running
        server.close()

def main():
    global LISTEN, LISTEN_AUTH, UPSTREAM, UPSTREAM_AUTH, DNS_SIDE, DNS_SERVER, DNS_TRANSPORT
    global RESOLVE_RULES, RESOLVE_RULES_EVERY, RATE_PER_CONN, QUEUE_TIMEOUT
    global _RULESET, _RATE, _SLOTS

    p = build_parser(full="--help" in sys.argv[1:])
    args = p.parse_args()
    setup_logging(args.verbose, args.quiet)

    # Handle default values defined at the top of the file
    try:
        if args.listen: LISTEN = parse_hostport(args.listen, LISTEN[1], LISTEN[0])
        if args.upstream: UPSTREAM = parse_hostport(args.upstream, UPSTREAM[1], UPSTREAM[0])
        if args.local: UPSTREAM = None
    except ValueError as e:
        p.error(f"Bad endpoint: {e}")
    RESOLVE_RULES = args.resolve_rules
    if args.resolve_rules_every is not None: RESOLVE_RULES_EVERY = args.resolve_rules_every
    RATE_PER_CONN = args.rate_per_conn
    if args.queue_timeout is not None: QUEUE_TIMEOUT = args.queue_timeout
    # by default the side the data goes to resolves the names as well
    DNS_SIDE = "local" if UPSTREAM is None else "upstream"
    if args.dns: DNS_SIDE, DNS_SERVER, DNS_TRANSPORT = args.dns
    if args.upstream_auth:
        user, _, password = args.upstream_auth.partition(":")
        UPSTREAM_AUTH = (user, password)
    if args.listen_auth:
        user, _, password = args.listen_auth.partition(":")
        LISTEN_AUTH = (user.encode(), password.encode())

    try: _RULESET = Ruleset(args.allow, args.block)
    except (OSError, ValueError) as e: p.error(f"Bad rule: {e}")

    try: load_hosts(args.hosts)
    except (OSError, ValueError) as e: p.error(f"Bad host mapping: {e}")

    # Safeguard impossible/weird argument combinations
    for name, entries in (("--listen", [args.listen]), ("--upstream", [args.upstream]),
                          ("--upstream-auth", [args.upstream_auth]),
                          ("--listen-auth", [args.listen_auth]), ("--allow", args.allow),
                          ("--block", args.block), ("--hosts", args.hosts),
                          ("--test-ruleset", args.test_ruleset)):
        for entry in entries or []:
            if entry is not None and entry.strip() == "":
                p.error(f"{name} was given an empty value")
    if args.verbose and args.quiet:
        p.error("--verbose and --quiet can't be used at the same time")
    if args.local and args.upstream:
        p.error("--local and --upstream are opposites: pick one")
    if UPSTREAM is None and args.upstream_auth:
        p.error("--upstream-auth makes no sense with --local")
    if args.upstream_auth and ":" not in args.upstream_auth:
        p.error("--upstream-auth is USER:PASS - write 'user:' for an empty password")
    if args.listen_auth and ":" not in args.listen_auth:
        p.error("--listen-auth is USER:PASS - write 'user:' for an empty password")
    if args.yes_resolve_rules and not RESOLVE_RULES:
        p.error("--yes-resolve-rules answers a question only --resolve-rules asks")
    if args.resolve_rules_every is not None and not RESOLVE_RULES:
        p.error("--resolve-rules-every paces --resolve-rules, which is not on")
    if RESOLVE_RULES_EVERY < 0:
        p.error("--resolve-rules-every cannot be negative, 0 resolves only once")
    if args.queue_timeout is not None and args.max_conns is None:
        p.error("--queue-timeout only makes sense with --max-conns specified")
    if QUEUE_TIMEOUT < 0:
        p.error("--queue-timeout cannot be negative, 0 waits forever")
    if args.max_conns is not None and args.max_conns < 1:
        p.error("--max-conns is how many connections run at once, so at least 1")
    if DNS_SIDE == "upstream" and UPSTREAM is None:
        p.error("--dns via upstream requires an upstream - you probably want '--dns local'")

    upstream_resolves = DNS_SIDE == "upstream" and DNS_SERVER is None
    if RESOLVE_RULES and upstream_resolves and any(
            rule.value[0] not in HOSTS for rule in _RULESET.resolveable_rules()):
        p.error("--resolve-rules does not work with basic upstream resolving because "
                "socksscope never sees the IP addresses - must use '--dns u:IP:tcp' for "
                "--resolve-rules to work with an upstream SOCKS5 proxy.")
    if upstream_resolves and any(rule.type == "ip" for rule in _RULESET.active):
        LOG.warning("probable unexpected ruleset! IP address connections can't be evaluated against "
            "domain name rules and connections made using a domain name can't be evaluated "
            "against IP address rules. Includes block and allow rules. This is due to using the "
            "upstream SOCKS5 server as a resolver. Switch to '--dns u:IP:tcp' to prevent that, or "
            "refuse domain names outright with '--block *' to only allow connections using IP addresses.")

    # Handle the initial resolving for '--resolve-rules'
    resolve_at_startup = RESOLVE_RULES and confirm_rule_resolving(p, args.yes_resolve_rules, test=bool(args.test_ruleset))
    if args.test_ruleset:
        if resolve_at_startup:
            try: asyncio.run(resolve_rules(startup=True))
            except (DNSError, OSError) as e: sys.exit(f"{p.prog}: {e}")
        try: return asyncio.run(test_ruleset(args.test_ruleset, resolved=resolve_at_startup))
        except ValueError as e: p.error(f"Bad --test-ruleset target: {e}")
    if RESOLVE_RULES and not resolve_at_startup:
        sys.exit("Stopping: the initial DNS queries for --resolve-rules were declined.")

    _RATE = TokenBucket(args.rate) if args.rate else None
    _SLOTS = asyncio.Semaphore(args.max_conns) if args.max_conns else None

    try: asyncio.run(serve())
    except KeyboardInterrupt: summarise_session()
    except (DNSError, OSError) as e: sys.exit(f"{p.prog}: {e}")

if __name__ == "__main__":
    sys.exit(main())