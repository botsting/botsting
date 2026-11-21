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
        written = [json.loads(line) for line in (tmp_path / "egress.jsonl").read_text(encoding="utf-8").splitlines()]
        assert written[0]["event"] == "started"
        lines = [line for line in written if "event" not in line]
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


# -- the log is a chain -----------------------------------------------------------------------


def a_finished_log(tmp_path):
    from promptproof.egress_trap import check_chain

    trap = EgressTrap(tmp_path / "egress.jsonl", allow=("api.example.invalid:443",))
    proxy = f"http://127.0.0.1:{trap.port}"
    with httpx.Client(proxy=proxy, timeout=5) as client:
        for path in ("a", "b", "c"):
            client.get(f"http://hooks.example.invalid/{path}")
    trap.stop()
    trap.stop()  # a second stop writes nothing
    lines = [json.loads(line) for line in (tmp_path / "egress.jsonl").read_text(encoding="utf-8").splitlines()]
    assert check_chain(lines) == ("intact", True)
    assert [line["n"] for line in lines] == [1, 2, 3, 4, 5] and lines[-1] == {**lines[-1], "event": "stopped", "attempts": 3}
    return lines, check_chain


def test_a_finished_log_is_an_intact_closed_chain(tmp_path):
    lines, _ = a_finished_log(tmp_path)
    assert lines[0]["allow"] == ["api.example.invalid:443"]


@pytest.mark.parametrize(
    ("tamper", "verdict"),
    [
        (lambda lines: lines[2].update(target="http://harmless.example/"), "broken at line 3"),  # a line edited
        (lambda lines: lines.pop(2), "broken at line 3"),  # a line removed
        (lambda lines: lines.insert(2, dict(lines[2])), "broken at line 4"),  # a line added
        (lambda lines: lines.__setitem__(slice(1, 3), [lines[2], lines[1]]), "broken at line 2"),  # reordered
        (lambda lines: lines[1].update(allowed="true"), "broken at line 2"),  # a refusal turned into an allowance
        (lambda lines: lines[-1].update(attempts=0), "broken at line 5"),  # the count edited
    ],
)
def test_any_change_after_writing_breaks_the_chain(tmp_path, tamper, verdict):
    lines, check_chain = a_finished_log(tmp_path)
    tamper(lines)
    assert check_chain(lines) == (verdict, False)


def test_a_log_cut_short_is_not_closed(tmp_path):
    lines, check_chain = a_finished_log(tmp_path)
    assert check_chain(lines[:-1]) == ("intact", False)  # the stop line is gone
    assert check_chain(lines[:2]) == ("intact", False)  # later attempts are gone too
    assert check_chain([]) == ("absent", False)
    assert check_chain([{"at": "t", "method": "GET", "target": "x"}]) == ("absent", False)  # an older log


def test_a_seal_reports_the_state_of_the_chain(tmp_path, capsys):
    from promptproof.cli import main
    from promptproof.seal import check, seal

    run = tmp_path / "run"
    run.mkdir()
    trap = EgressTrap(run / "egress-trap.jsonl")
    with httpx.Client(proxy=f"http://127.0.0.1:{trap.port}", timeout=5) as client:
        client.get("http://hooks.example.invalid/x")
    trap.stop()
    value = seal(run, tmp_path / "good.zip")
    egress = check(tmp_path / "good.zip", value)["egress"]
    assert egress["chain"] == "intact" and egress["closed"] is True
    assert egress["refused"] == {"http://hooks.example.invalid/x": 1} and egress["unreadable_lines"] == 0
    assert main(["check-seal", str(tmp_path / "good.zip")]) == 0
    assert "ends with the trap's stop line" in capsys.readouterr().out

    # Someone removes the refused attempt before sealing: the seal is honest about the log it was given.
    log = run / "egress-trap.jsonl"
    kept = [line for line in log.read_text(encoding="utf-8").splitlines() if "hooks.example" not in line]
    log.write_text("\n".join(kept) + "\n", encoding="utf-8")
    seal(run, tmp_path / "edited.zip")
    assert check(tmp_path / "edited.zip")["egress"]["chain"] == "broken at line 2"
    assert main(["check-seal", str(tmp_path / "edited.zip")]) == 1
    printed = capsys.readouterr().out
    assert "THE CHAIN IS BROKEN AT LINE 2" in printed and "cannot be relied on" in printed
