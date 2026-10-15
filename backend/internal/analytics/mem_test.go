package analytics

import (
	"runtime"
	"testing"
	"time"
)

// Reports heap cost per event so MAX_EVENTS can be sized for small VMs.
func TestMemoryPerEvent(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	evs := synth(100000)
	runtime.GC()
	runtime.ReadMemStats(&after)
	per := float64(after.HeapAlloc-before.HeapAlloc) / float64(len(evs))
	start := time.Now()
	ds := Build(Params{Range: "all"}, time.Time{}, time.Time{}, evs)
	runtime.GC()
	var built runtime.MemStats
	runtime.ReadMemStats(&built)
	t.Logf("events: %.0f B/event raw; derived sessions+attackers add %.1f MB; build %v for %d events",
		per, float64(built.HeapAlloc-after.HeapAlloc)/1e6, time.Since(start), len(ds.Events))
}
