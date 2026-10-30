#!/usr/bin/env python3
"""Deterministic AgentLoupe demo workload (tracked in the repo).

Run by scripts/demo.sh as ``python3 examples/loupe_demo.py`` — the
``loupe_demo`` marker in argv is what configs/loupe-demo.yaml confirms
the session by. Exercises, with no internet access:

  * a child process (``echo``),
  * file write + read under a fresh temp dir,
  * one TCP and one UDP connect, both to listeners this same process
    starts on 127.0.0.1 with ephemeral ports.

Everything is fixed-content and self-contained, so two runs should
produce the same shape of session for the scorecard/timeline.
"""
import socket
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="loupe-demo-") as tmp:
        path = Path(tmp) / "demo.txt"
        path.write_text("agentloupe demo\n", encoding="utf-8")
        if path.read_text(encoding="utf-8") != "agentloupe demo\n":
            raise SystemExit("loupe_demo: file read-back mismatch")

    subprocess.run(["echo", "agentloupe-demo"], check=True)

    # TCP: listener and client are both this process (no internet).
    with socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=5) as client:
            conn, _ = listener.accept()
            with conn:
                client.sendall(b"x")
                if conn.recv(1) != b"x":
                    raise SystemExit("loupe_demo: TCP echo mismatch")

    # UDP: a connect() on a datagram socket + one datagram to our listener.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.settimeout(5)
        receiver.bind(("127.0.0.1", 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.connect(receiver.getsockname())
            client.send(b"x")
            data, _ = receiver.recvfrom(1)
            if data != b"x":
                raise SystemExit("loupe_demo: UDP payload mismatch")

    print("loupe_demo: ok")


if __name__ == "__main__":
    main()
