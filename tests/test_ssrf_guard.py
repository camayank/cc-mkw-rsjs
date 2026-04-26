"""SSRF guard for the public free-scan endpoints.

Proves the public scan inputs reject hostnames that would otherwise turn
the server into an internal-network probe:

  - literal localhost / broadcast names
  - any name with a non-public TLD suffix (.local, .internal, .corp, etc.)
  - any name that DNS-resolves to a private / loopback / link-local /
    multicast / reserved IP
  - malformed hostnames

Real public domains continue to pass.
"""
from __future__ import annotations

import os
import sys
import socket

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def gate(monkeypatch):
    """Reload main + stub DNS so tests don't depend on the network."""
    sys.modules.pop("main", None)
    import main as m

    def fake_resolve(name):
        # Map test names to canned IPs.
        table = {
            "localhost":            [("127.0.0.1",)],
            "metadata.google.internal": [("169.254.169.254",)],
            "internal.corp":        [("10.0.0.5",)],
            "private-thing.com":    [("192.168.1.10",)],
            "link-local.example":   [("169.254.0.42",)],
            "multicast.example":    [("224.0.0.1",)],
            "ipv6-loop.example":    [("::1",)],
            "good.example.com":     [("93.184.216.34",)],   # example.com
            "another-public.com":   [("8.8.8.8",)],
        }
        if name not in table:
            raise socket.gaierror("name unknown in test stub")
        return [(socket.AF_INET, None, None, None, (entry[0], 0))
                for entry in table[name]]

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **kw: fake_resolve(host))
    return m._validate_public_scan_target


# ─── Suffix / literal blocks ─────────────────────────────────


@pytest.mark.parametrize("bad", [
    "localhost",
    "anything.local",
    "internal.corp",
    "x.lan",
    "x.intranet",
    "x.home",
    "x.test",
    "x.invalid",
    "x.example",
    "x.onion",
])
def test_internal_suffixes_rejected(gate, bad):
    with pytest.raises(Exception):
        gate(bad)


def test_literal_localhost_rejected(gate):
    with pytest.raises(Exception):
        gate("localhost")


# ─── Resolves-to-internal-IP blocks ──────────────────────────


@pytest.mark.parametrize("bad", [
    "metadata.google.internal",
    "private-thing.com",
    "link-local.example",
    "multicast.example",
    "ipv6-loop.example",
])
def test_internal_addresses_rejected(gate, bad):
    """Even when the hostname is innocuous, a non-public resolved address
    must abort the scan."""
    with pytest.raises(Exception):
        gate(bad)


# ─── Malformed input rejected ────────────────────────────────


@pytest.mark.parametrize("bad", [
    "",
    "not a domain",
    "no-tld",
    "underscore_name.com",
    "spaces in.com",
    "http://attack/",
])
def test_malformed_rejected(gate, bad):
    with pytest.raises(Exception):
        gate(bad)


# ─── Public hostnames pass ───────────────────────────────────


def test_public_hostname_accepted(gate):
    out = gate("good.example.com")
    assert out == "good.example.com"


def test_strips_scheme_and_path(gate):
    # https://good.example.com/path?x=1 → good.example.com
    out = gate("HTTPS://good.example.com/path?x=1")
    assert out == "good.example.com"


# ─── Route-level: SSE stream and POST /api/scan/free ─────────


def test_free_scan_stream_rejects_internal_domain(test_client, monkeypatch):
    def fake(host, *a, **kw):
        if host == "metadata.google.internal":
            return [(socket.AF_INET, None, None, None, ("169.254.169.254", 0))]
        raise socket.gaierror("unknown")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    resp = test_client.get("/api/scan/free/stream",
                            params={"domain": "metadata.google.internal"})
    assert resp.status_code == 400
    assert "non-public" in resp.text.lower() or "not eligible" in resp.text.lower()


def test_free_scan_post_rejects_internal_domain(test_client, monkeypatch):
    def fake(host, *a, **kw):
        return [(socket.AF_INET, None, None, None, ("10.0.0.7", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    resp = test_client.post("/api/scan/free", json={"domain": "private.example.com"})
    assert resp.status_code == 400


def test_free_scan_post_rejects_localhost(test_client):
    resp = test_client.post("/api/scan/free", json={"domain": "localhost"})
    assert resp.status_code == 400


def test_free_scan_post_rejects_internal_suffix(test_client):
    resp = test_client.post("/api/scan/free", json={"domain": "thing.internal"})
    assert resp.status_code == 400
