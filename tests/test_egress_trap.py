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
