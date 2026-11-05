package app

import (
	"time"
)

// CaptureMetaType is the JSONL type of the one capture-level record the
// loader writes before any session event. It belongs to no session
// (session_id 0) and readers that group by session must skip it.
const CaptureMetaType = "capture_meta"

// captureMetaRecord describes how to interpret the capture's clocks and
// which opt-in probes were requested/attached, so reducers can tell "0"
// (measured) from "not collected" (null) and can map timestamps from
// other sources (harness hooks) into the capture's time domain exactly.
//
// Clock contract: every event's `ts` is wall_base + ktime, where ktime is
// bpf_ktime_get_ns() — CLOCK_MONOTONIC, which excludes suspend and is
// slewed (never stepped) by NTP. wall_base_unix_ns is CLOCK_REALTIME
// minus CLOCK_MONOTONIC sampled once at loader start. A CLOCK_MONOTONIC
// reading taken by any process on the same host therefore converts to
// capture time as wall_base_unix_ns + mono_ns with no estimation.
// CLOCK_REALTIME readings agree with capture `ts` only to within the
// realtime/monotonic drift accrued since loader start (suspend, NTP
// steps); realtime_ns/monotonic_ns sampled at emission let a reader
// check that drift was ~0 at the start.
func captureMetaRecord(wallBase time.Time, realNow time.Time, monoNowNS int64, probes map[string]bool) Output {
	return Output{
		Ts:   wallBase.Add(time.Duration(monoNowNS)).UTC().Format(time.RFC3339Nano),
		Type: CaptureMetaType,
		Fields: map[string]any{
			"abi_version":       8,
			"clock":             "CLOCK_MONOTONIC",
			"ts_formula":        "wall_base_unix_ns + bpf_ktime_get_ns",
			"wall_base":         wallBase.UTC().Format(time.RFC3339Nano),
			"wall_base_unix_ns": wallBase.UnixNano(),
			"realtime_ns":       realNow.UnixNano(),
			"monotonic_ns":      monoNowNS,
			"probes":            probes,
		},
	}
}

// newCaptureMeta samples the clocks now and builds the record.
func newCaptureMeta(wallBase time.Time, probes map[string]bool) Output {
	realNow := time.Now()
	var mono int64
	if ts, err := monotonicTimespec(); err == nil {
		mono = ts.Sec*1_000_000_000 + ts.Nsec
	} else {
		mono = realNow.Sub(wallBase).Nanoseconds()
	}
	return captureMetaRecord(wallBase, realNow, mono, probes)
}
