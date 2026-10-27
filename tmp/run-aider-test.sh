#!/bin/bash
cd "$(dirname "$0")/.." || exit 1
./agentloupe --config tmp/aider-agents.yaml \
  --bpf-object bpf/agentloupe.bpf.o --max-runtime 20s \
  > tmp/aider.jsonl 2> tmp/aider.log &
sleep 3
python3 tmp/aider_probe.py
python3 -c 'print(999)'
wait
echo "=== CONFIRM/REJECT SUMMARY ==="
grep -v file_open tmp/aider.jsonl
echo "file_open lines: $(grep -c file_open tmp/aider.jsonl)"
echo "=== LOG ==="
grep -v "config reloaded" tmp/aider.log
