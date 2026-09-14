"""Shared fixtures + an upfront check that the dependencies are importable"""
import importlib.util
import os, subprocess, time
from pathlib import Path

import pytest

# clients.py imports dnspython at module load, so check before that import -
# otherwise a missing venv shows a raw ImportError instead of this message.
if importlib.util.find_spec("dns.message") is None:
    raise pytest.UsageError(
        "Missing test prerequisite: dnspython"
        "\nRun pytest with the repo venv interpreter, e.g. `.venv/bin/python -m pytest`.")

from clients import BulkServer, DNSServer, free_port, port_open, socksscope_cmd, wait_until

# pyproject.toml setup
#   [tool.coverage.run]
#   source = ["socksscope"]
#   parallel = true    # one data file per spawned process; `coverage combine` merges them
#   sigterm = true     # the proxy fixture stops socksscope with terminate() (SIGTERM)
#   branch = true


def pytest_addoption(parser):
    parser.addoption("--coverage", action="store_true", default=False,
                     help="Measure coverage of the spawned socksscope.py processes "
                          "(writes .coverage.* files; run `coverage combine` after)")


def pytest_configure(config):
    # Bridge the flag to an env var; socksscope_cmd() is a plain module function
    # without access to the pytest config.
    if config.getoption("--coverage"):
        os.environ["SOCKSSCOPE_COV"] = "1"


class Proxy:
    """A running socksscope process plus the log it is writing

    stderr goes to a file rather than a pipe so a test can read the log while
    the process is still running, which the queueing tests need.
    """

    def __init__(self, proc, port, log_path):
        self.proc = proc
        self.port = port
        self._log_path = Path(log_path)

    @property
    def log(self):
        return self._log_path.read_text() if self._log_path.exists() else ""

    def wait_for(self, text, timeout=5):
        """Wait for a line to show up in the log; returns whether it did"""
        return wait_until(lambda: text in self.log, timeout)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return self.log


@pytest.fixture
def proxy(tmp_path):
    """Factory that spawns socksscope instances and cleans them up

    Usage: p = proxy("--local", "--allow", "127.0.0.1") then drive p.port
    """
    started = []

    def _start(*args, listen=None, wait=True):
        port = listen or free_port()
        log_path = tmp_path / f"socksscope_{port}.log"
        cmd = [*socksscope_cmd(), "-l", f"127.0.0.1:{port}", *map(str, args)]
        with open(log_path, "w") as log_file:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=log_file, text=True)
        instance = Proxy(proc, port, log_path)
        started.append(instance)
        if wait:
            wait_until(lambda: port_open(port) or proc.poll() is not None)
            time.sleep(0.15)
        return instance

    yield _start
    for instance in started:
        instance.stop()


@pytest.fixture
def target():
    """A TCP target that hands out a fixed payload"""
    server = BulkServer()
    yield server
    server.stop()


@pytest.fixture
def dns_server():
    """Factory for a DNS/TCP server over a fixed zone

    Usage: d = dns_server({"host.corp.local": ["127.0.0.1"]})
    """
    started = []

    def _start(zone, transport="tcp"):
        server = DNSServer(zone, transport)
        started.append(server)
        return server

    yield _start
    for server in started:
        server.stop()


@pytest.fixture
def upstream(proxy):
    """A plain socksscope acting as the 'existing proxy' the tests chain through

    Its log doubles as a record of what socksscope asked it for, which is how
    the DNS tests tell a rewritten request (an IP) from a passed-through name -
    so it runs with -v, where the per-connection lines live.
    """
    return proxy("--local", "-v")
