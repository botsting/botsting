"""A trap for outbound web traffic from a bot under test.

Start it, then start the bot with HTTP_PROXY and HTTPS_PROXY pointing at it (and
NO_PROXY covering only this machine). Every web request the bot tries to make to
anywhere else arrives here instead. The trap refuses all of them, sends nothing on,
and writes one JSON line per attempt to its log, so after the test the log shows
exactly what the bot tried to reach. An empty log is the evidence that it reached
for nothing.

Limits, stated in every report that relies on it: this catches traffic that honours
the proxy settings (ordinary HTTP clients do, unless a program turns that off). It
does not see raw TCP connections such as SMTP or a database protocol, so it is used
together with a check of the bot's open connections, not instead of it.
"""

from __future__ import annotations

import json
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path

_MAX_HEADER = 16_384


class EgressTrap:
    def __init__(self, log_path: Path, host: str = "127.0.0.1", port: int = 0) -> None:
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("the trap only listens on this machine")
        self.log_path = Path(log_path)
        self.attempts: list[dict[str, str]] = []
        self._lock = threading.Lock()
        self._server = socket.create_server((host, port))
        self.port = self._server.getsockname()[1]
        self._stopped = threading.Event()
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
            self._record(method or "(nothing)", target or "(nothing)")
            try:
                connection.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass

    def _record(self, method: str, target: str) -> None:
        entry = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "method": method, "target": target}
        with self._lock:
            self.attempts.append(entry)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(entry) + "\n")

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
        self._stopped.set()
        self._server.close()
