"""A trap for outbound web traffic from a bot under test.

Start it, then start the bot with HTTP_PROXY and HTTPS_PROXY pointing at it (and
NO_PROXY covering only this machine). Every web request the bot tries to make to
anywhere else arrives here instead. The trap refuses all of them, sends nothing on,
and writes one JSON line per attempt to its log, so after the test the log shows
exactly what the bot tried to reach. An empty log is the evidence that it reached
for nothing.

A test sometimes needs one outside service, such as the bot's model API. Name it in
`allow` as "host:port"; an encrypted tunnel (CONNECT) to exactly that address is then
passed through and recorded as allowed. Everything else is still refused. The trap
sees only where a tunnel goes, not what is inside it.

The log is a chain. Every line carries its number and a hash of itself and the line
before it, the first line records the start and the last line the stop, with the count.
So a line that is changed, removed, added or reordered afterwards breaks the chain, and
a log cut short has no closing line. `botsting seal` checks both and says so.

What the chain does not stop: the hashes use no secret, so someone who rewrites the
whole log and recomputes every hash produces a log that checks. The chain catches a
partial edit; a full rewrite is caught by the seal, made when the run ended and shared
separately. Like the seal, the chain cannot show that the program writing the log was
honest.

No scan starts the trap by itself: a scan does not start the bot either. Run it next to
the bot, for example when testing a copy of a real system:

    botsting egress-trap --log run/egress-trap.jsonl --allow api.anthropic.com:443

It prints the proxy settings to start the bot with, runs until Ctrl+C, and closes the
log. Put the log in the run's folder before sealing it.

Limits, stated in every report that relies on it: this catches traffic that honours
the proxy settings (ordinary HTTP clients do, unless a program turns that off). It
does not see raw TCP connections such as SMTP or a database protocol, so it is used
together with a check of the bot's open connections, not instead of it.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path

from botsting.exits import EXIT_FAILED, EXIT_OK

_MAX_HEADER = 16_384
CHAIN_START = hashlib.sha256(b"botsting-egress/1").hexdigest()


def chain_hash(previous: str, entry: dict[str, object]) -> str:
    """The hash that links `entry` (without its own "chain" field) to the line before it."""
    body = {key: value for key, value in entry.items() if key != "chain"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((previous + "|" + canonical).encode("ascii")).hexdigest()


def check_chain(lines: list[dict[str, object]]) -> tuple[str, bool]:
    """("absent" | "intact" | "broken at line N", closed). `closed` means the log ends with the trap's own
    stop line and its count matches, so nothing was cut off the end."""
    if not any("chain" in line for line in lines):
        return "absent", False
    previous = CHAIN_START
    for number, line in enumerate(lines, start=1):
        if line.get("n") != number or line.get("chain") != chain_hash(previous, line):
            return f"broken at line {number}", False
        previous = str(line["chain"])
    first, last = lines[0], lines[-1]
    attempts = sum(1 for line in lines if "event" not in line)
    closed = first.get("event") == "started" and last.get("event") == "stopped" and last.get("attempts") == attempts
    return "intact", closed


class EgressTrap:
    def __init__(
        self, log_path: Path, host: str = "127.0.0.1", port: int = 0, allow: tuple[str, ...] = ()
    ) -> None:
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the trap only listens on this machine")
        for item in allow:
            name, _, number = item.rpartition(":")
            if not name or not number.isdigit():
                raise ValueError(f"allow entries are host:port, got {item!r}")
        self.allow = frozenset(item.lower() for item in allow)
        self.log_path = Path(log_path)
        self.attempts: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._server = socket.create_server((host, port))
        self.port = self._server.getsockname()[1]
        self._stopped = threading.Event()
        self._lines = 0
        self._chain = CHAIN_START
        self._write({"event": "started", "allow": sorted(self.allow)})
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        self._server.settimeout(0.2)
        while not self._stopped.is_set():
            try:
                connection, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._refuse, args=(connection,), daemon=True).start()

    def _refuse(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(5)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < _MAX_HEADER:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            method, _, rest = first.partition(" ")
            target = rest.rsplit(" ", 1)[0] if " " in rest else rest
            if method == "CONNECT" and target.lower() in self.allow:
                self._record(method, target, allowed=True)
                head, _, early = data.partition(b"\r\n\r\n")
                self._tunnel(connection, target, early)
                return
            self._record(method or "(nothing)", target or "(nothing)")
            try:
                connection.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass

    def _tunnel(self, client: socket.socket, target: str, early: bytes) -> None:
        """Pass an encrypted tunnel through to an allowed address, untouched, until either side closes."""
        host, _, port = target.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=15)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        with upstream:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if early:
                upstream.sendall(early)
            client.settimeout(None)
            upstream.settimeout(None)

            def pump(source: socket.socket, sink: socket.socket) -> None:
                try:
                    while chunk := source.recv(65536):
                        sink.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for side in (source, sink):
                        try:
                            side.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            back = threading.Thread(target=pump, args=(upstream, client), daemon=True)
            back.start()
            pump(client, upstream)
            back.join(timeout=5)

    def _record(self, method: str, target: str, allowed: bool = False) -> None:
        entry = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "method": method, "target": target}
        if allowed:
            entry["allowed"] = "true"
        self.attempts.append(self._write(entry))

    def _write(self, entry: dict[str, object]) -> dict[str, object]:
        """Append one line, numbered and chained to the line before."""
        with self._lock:
            self._lines += 1
            entry = {"at": datetime.now(UTC).isoformat(timespec="seconds"), **entry, "n": self._lines}
            entry["chain"] = self._chain = chain_hash(self._chain, entry)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(entry) + chr(10))
            return entry

    def proxy_environment(self) -> dict[str, str]:
        """Environment variables that send a program's web traffic here, except to this machine."""
        url = f"http://127.0.0.1:{self.port}"
        return {
            "HTTP_PROXY": url,
            "HTTPS_PROXY": url,
            "http_proxy": url,
            "https_proxy": url,
            "ALL_PROXY": url,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1",
        }

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        self._server.close()
        self._write({"event": "stopped", "attempts": len(self.attempts)})


def _command(args: object) -> int:
    import time

    try:
        trap = EgressTrap(Path(args.log), port=args.port, allow=tuple(args.allow))  # type: ignore[attr-defined]
    except (ValueError, OSError) as error:
        print(f"error: {error}")
        return EXIT_FAILED
    print(f"Trap listening on 127.0.0.1:{trap.port}. Log: {Path(args.log).resolve()}")  # type: ignore[attr-defined]
    print(f"Passed through: {', '.join(sorted(trap.allow)) or 'nothing'}. Everything else is refused and recorded.")
    print("Start the bot with these settings, so that its web traffic comes here:")
    for name, value in trap.proxy_environment().items():
        print(f"  {name}={value}")
    print("It sees traffic that honours proxy settings, not raw connections such as a database's. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        trap.stop()
    refused = sum(1 for attempt in trap.attempts if attempt.get("allowed") != "true")
    print(f"Stopped. {len(trap.attempts)} outbound attempt(s) recorded, {refused} refused. The log is closed.")
    return EXIT_OK


def register(commands: object) -> None:
    parser = commands.add_parser(  # type: ignore[attr-defined]
        "egress-trap", help="record, and refuse, the outbound web traffic of a bot you run next to it"
    )
    parser.add_argument("--log", required=True, help="where to write the log, for example run/egress-trap.jsonl")
    parser.add_argument("--allow", action="append", default=[], metavar="HOST:PORT", help="a destination to pass through, such as the bot's model service (repeat for each)")
    parser.add_argument("--port", type=int, default=0, help="the port to listen on (default: a free one)")
    parser.set_defaults(handler=_command)
