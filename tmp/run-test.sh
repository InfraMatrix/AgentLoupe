#!/bin/bash
# One-shot diagnostic: run loader, probe from kernel side while live.
cd "$(dirname "$0")/.." || exit 1
./agentloupe --config tmp/test-agents.yaml \
  --bpf-object bpf/agentloupe.bpf.o --max-runtime 20s \
  > tmp/al5.jsonl 2> tmp/al5.log &
sleep 3
echo "=== PROGS ==="
bpftool prog show | grep handle_enter
python3 tmp/aider_probe.py
echo "=== COUNTERS (kernel ground truth) ==="
bpftool map dump name counters
wait
echo "=== JSONL ==="
cat tmp/al5.jsonl
echo "=== LOG ==="
cat tmp/al5.log
