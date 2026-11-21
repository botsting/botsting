"""The outbound trap refuses and records every request sent through it, and sends nothing on."""

import json

import httpx
import pytest

from promptproof.egress_trap import EgressTrap


def test_requests_through_the_trap_are_refused_and_recorded(tmp_path):
    trap = EgressTrap(tmp_path / "egress.jsonl")
    try:
        proxy = f"http://127.0.0.1:{trap.port}"
        with httpx.Client(proxy=proxy, timeout=5) as client:
            plain = client.get("http://api.example.invalid/v1/messages")
            assert plain.status_code == 403
            with pytest.raises(httpx.ProxyError):
                client.get("https://api.anthropic.invalid/v1/messages")
        lines = [json.loads(line) for line in (tmp_path / "egress.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [(a["method"], a["target"]) for a in lines] == [
            ("GET", "http://api.example.invalid/v1/messages"),
            ("CONNECT", "api.anthropic.invalid:443"),
        ]
        assert trap.attempts == lines
    finally:
        trap.stop()


def test_the_trap_only_listens_on_this_machine(tmp_path):
    with pytest.raises(ValueError):
        EgressTrap(tmp_path / "x.jsonl", host="0.0.0.0")


def test_the_proxy_environment_exempts_only_this_machine(tmp_path):
    trap = EgressTrap(tmp_path / "x.jsonl")
    try:
        env = trap.proxy_environment()
        assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == f"http://127.0.0.1:{trap.port}"
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
    finally:
        trap.stop()


def test_an_allowed_tunnel_is_passed_through_and_everything_else_still_refused(tmp_path):
    import socket
    import threading

    upstream = socket.create_server(("127.0.0.1", 0))
    port = upstream.getsockname()[1]

    def echo():
        connection, _ = upstream.accept()
        with connection:
            while data := connection.recv(1024):
                connection.sendall(b"echo:" + data)

    threading.Thread(target=echo, daemon=True).start()
    trap = EgressTrap(tmp_path / "egress.jsonl", allow=(f"127.0.0.1:{port}",))
    try:
        with socket.create_connection(("127.0.0.1", trap.port), timeout=5) as client:
            client.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            assert client.recv(1024).startswith(b"HTTP/1.1 200")
            client.sendall(b"hello")
            assert client.recv(1024) == b"echo:hello"
        with socket.create_connection(("127.0.0.1", trap.port), timeout=5) as client:
            client.sendall(f"CONNECT 127.0.0.1:{port + 1} HTTP/1.1\r\n\r\n".encode())
            assert client.recv(1024).startswith(b"HTTP/1.1 403")
        assert [(a["target"], a.get("allowed")) for a in trap.attempts] == [
            (f"127.0.0.1:{port}", "true"),
            (f"127.0.0.1:{port + 1}", None),
        ]
    finally:
        trap.stop()
        upstream.close()


def test_allow_entries_must_name_host_and_port(tmp_path):
    with pytest.raises(ValueError, match="host:port"):
        EgressTrap(tmp_path / "x.jsonl", allow=("api.anthropic.com",))
