package app

import (
	"encoding/json"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

type jsonEncoder struct{ w io.Writer }

func (e jsonEncoder) Encode(v any) error {
	return json.NewEncoder(e.w).Encode(v)
}

func monotonicTimespec() (unix.Timespec, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts, err
}

var _ = time.Now
