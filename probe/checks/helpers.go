package checks

import (
	"strconv"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// msSince returns milliseconds elapsed since start, as a float.
func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func paramInt(spec protocol.CheckSpec, key string, def int) int {
	if v, ok := spec.Params[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func paramString(spec protocol.CheckSpec, key, def string) string {
	if v, ok := spec.Params[key]; ok && v != "" {
		return v
	}
	return def
}

func paramDuration(spec protocol.CheckSpec, key string, def time.Duration) time.Duration {
	if n := paramInt(spec, key, 0); n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}
