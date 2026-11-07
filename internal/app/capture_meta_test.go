package app

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestCaptureMetaRecordClockContract(t *testing.T) {
	wallBase := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	mono := int64(5_000_000_123)
	real := wallBase.Add(time.Duration(mono))
	rec := captureMetaRecord(wallBase, real, mono, map[string]bool{"file_rw_events": true})
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != CaptureMetaType || m["clock"] != "CLOCK_MONOTONIC" {
		t.Fatalf("bad header: %v", m)
	}
	if sid, _ := m["session_id"].(json.Number).Int64(); sid != 0 {
		t.Fatalf("capture_meta must not belong to a session, got %d", sid)
	}
	if v, _ := m["abi_version"].(json.Number).Int64(); v != abiVersion {
		t.Fatalf("capture_meta abi_version = %d, want %d (the decoder's)", v, abiVersion)
	}
	base, _ := m["wall_base_unix_ns"].(json.Number).Int64()
	if base != wallBase.UnixNano() {
		t.Fatalf("wall_base_unix_ns = %d, want %d", base, wallBase.UnixNano())
	}
	// ts must follow the same formula as every event: wall_base + mono.
	ts, err := time.Parse(time.RFC3339Nano, m["ts"].(string))
	if err != nil || !ts.Equal(wallBase.Add(time.Duration(mono))) {
		t.Fatalf("ts %v does not equal wall_base+mono", m["ts"])
	}
	probes, ok := m["probes"].(map[string]any)
	if !ok || probes["file_rw_events"] != true {
		t.Fatalf("probes missing: %v", m["probes"])
	}
}
