# Canned real-agent run (offline demo)

One real run of `examples/real-agent/run.sh` (2026-11-05, kernel
7.0.0-42-generic, LSM mode, Claude Code 2.1.318): Claude Code was asked
to set up a venv in a NetworkX 3.5 checkout with an injected one-line
Dijkstra bug, fix it, and run the full suite. It made 5 tool calls
(3 Bash, Read, Edit) in 60s and fixed the bug; the final suite run passed.

`make demo-canned` renders all of it with no sudo and no network.

| File | What |
|---|---|
| `capture.jsonl` | Loader capture (`--catalog-only claude-code --enable-syscall-summary --enable-io-accounting --enable-net-send-events --drop-path-prefix /proc/`), reduced by `scripts/make_canned.py` to the demo session plus its nested `rg` session (other Claude Code processes on the host were adopted too and are dropped). |
| `capture.spans.jsonl` | The 10 hook records (`hooks/forkline_hook.py`, 5 pre/post pairs). |
| `report.json` | `forkline-timeline --json` of the two files above. |
| `analysis.report.json`, `analysis.md` | AgentCutter `analyze` (real Muse Spark call). |

Sanitized: the work dir is `/work`, the home dir is `/u/demo`, and the user name
is `demo`. Some paths appear as `/forkline-real-agent/...` without `/tmp`:
in LSM mode, exec `cwd` comes from the bounded dentry walk, which misses
the tmpfs mount prefix (see the README fidelity note).
