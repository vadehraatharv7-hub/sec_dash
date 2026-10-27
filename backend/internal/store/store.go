// Package store keeps recent events in memory for fast analytics and writes
// them through to a Persister (MongoDB in production).
package store

import (
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"sec_dash/backend/internal/model"
)

// Persister is the durable backend. Documents of auxiliary collections
// (bans, webhooks, ...) are stored as JSON-friendly maps keyed by string.
type Persister interface {
	Insert(evs []*model.Event) error
	Load(limit int) ([]*model.Event, error)
	UpdateGeo(ip string, g model.Geo) error
	PutDoc(coll, key string, doc map[string]interface{}) error
	DelDoc(coll, key string) error
	ListDocs(coll string) ([]map[string]interface{}, error)
	Close() error
}

// Store is the in-memory event index.
type Store struct {
	mu      sync.RWMutex
	events  []*model.Event // sorted by Time ascending
	max     int
	version atomic.Int64
	p       Persister

	subMu sync.Mutex
	subs  map[chan *model.Event]struct{}

	knownSensors map[string]string // sensor -> source

	seen    map[string]struct{} // fingerprints of recent events (drops re-sent duplicates)
	seenOrd []string
}

const seenCap = 200000

// New creates a store and loads recent events from the persister.
func New(p Persister, max int) *Store {
	s := &Store{p: p, max: max, subs: map[chan *model.Event]struct{}{}, knownSensors: map[string]string{}, seen: map[string]struct{}{}}
	if p != nil {
		evs, err := p.Load(max)
		if err != nil {
			log.Printf("[store] load failed: %v", err)
		} else {
			sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
			// Earlier versions could store an event more than once; keep one copy of each.
			uniq := evs[:0]
			for _, e := range evs {
				if s.remember(e) {
					uniq = append(uniq, e)
					s.knownSensors[e.Sensor] = e.Source
				}
			}
			s.events = uniq
			log.Printf("[store] loaded %d events (%d duplicates ignored)", len(uniq), len(evs)-len(uniq))
		}
	}
	s.version.Add(1)
	return s
}

func (s *Store) Persister() Persister { return s.p }

// Version changes whenever event data changes; used for cache invalidation.
func (s *Store) Version() int64 { return s.version.Load() }

// remember records the event's fingerprint and reports whether it is new.
func (s *Store) remember(e *model.Event) bool {
	fp := e.Fingerprint()
	if _, dup := s.seen[fp]; dup {
		return false
	}
	s.seen[fp] = struct{}{}
	s.seenOrd = append(s.seenOrd, fp)
	if len(s.seenOrd) > seenCap {
		for _, old := range s.seenOrd[:seenCap/10] {
			delete(s.seen, old)
		}
		s.seenOrd = append([]string(nil), s.seenOrd[seenCap/10:]...)
	}
	return true
}

// Add stores events: it persists them first and only then makes them visible and
// remembers them, so a failed database write leaves no trace and the caller can send the
// same batch again. Events already seen (same content and millisecond) are dropped, so a
// sensor that re-sends a batch cannot double-count.
//
// It returns an error only when persisting failed. Nothing was stored in that case.
func (s *Store) Add(evs []*model.Event, persist bool) error {
	if len(evs) == 0 {
		return nil
	}
	s.mu.Lock()
	fresh := evs[:0:0]
	batch := map[string]bool{}
	for _, e := range evs {
		fp := e.Fingerprint()
		if _, dup := s.seen[fp]; dup || batch[fp] {
			continue
		}
		batch[fp] = true
		fresh = append(fresh, e)
	}
	s.mu.Unlock()
	if len(fresh) == 0 {
		return nil
	}

	// The insert is idempotent (deterministic _id), so concurrent or repeated attempts are safe.
	if persist && s.p != nil {
		if err := s.p.Insert(fresh); err != nil {
			return err
		}
	}

	s.mu.Lock()
	added := fresh[:0:0]
	for _, e := range fresh {
		if !s.remember(e) {
			continue
		}
		added = append(added, e)
		n := len(s.events)
		if n == 0 || !e.Time.Before(s.events[n-1].Time) {
			s.events = append(s.events, e)
		} else {
			i := sort.Search(n, func(i int) bool { return s.events[i].Time.After(e.Time) })
			s.events = append(s.events, nil)
			copy(s.events[i+1:], s.events[i:])
			s.events[i] = e
		}
		s.knownSensors[e.Sensor] = e.Source
	}
	if over := len(s.events) - s.max; over > s.max/10 {
		s.events = append([]*model.Event(nil), s.events[over:]...)
	}
	s.mu.Unlock()
	s.version.Add(1)

	s.subMu.Lock()
	for ch := range s.subs {
		for _, e := range added {
			select {
			case ch <- e:
			default:
			}
		}
	}
	s.subMu.Unlock()
	return nil
}

// SetGeo applies a resolved location to every in-memory event of an IP.
func (s *Store) SetGeo(ip string, g model.Geo) {
	s.mu.Lock()
	for _, e := range s.events {
		if e.IP == ip {
			e.Geo = g
		}
	}
	s.mu.Unlock()
	s.version.Add(1)
	if s.p != nil {
		if err := s.p.UpdateGeo(ip, g); err != nil {
			log.Printf("[store] geo persist failed: %v", err)
		}
	}
}

// IPsMissingGeo lists public IPs in memory that have no location yet.
func (s *Store) IPsMissingGeo() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range s.events {
		if e.IP != "" && e.Geo.CountryCode == "" && !seen[e.IP] {
			seen[e.IP] = true
			out = append(out, e.IP)
		}
	}
	return out
}

// View runs fn with a read-locked, time-sorted slice. fn must not retain it.
func (s *Store) View(fn func(all []*model.Event)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.events)
}

// Range returns a copy of the events in [from, to) (zero values = unbounded)
// optionally limited to one sensor.
func (s *Store) Range(from, to time.Time, sensor string) []*model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lo, hi := 0, len(s.events)
	if !from.IsZero() {
		lo = sort.Search(len(s.events), func(i int) bool { return !s.events[i].Time.Before(from) })
	}
	if !to.IsZero() {
		hi = sort.Search(len(s.events), func(i int) bool { return !s.events[i].Time.Before(to) })
	}
	if lo > hi {
		lo = hi
	}
	out := make([]*model.Event, 0, hi-lo)
	for _, e := range s.events[lo:hi] {
		if sensor == "" || sensor == "all" || e.Sensor == sensor {
			out = append(out, e)
		}
	}
	return out
}

// Sensors returns the known sensor names and their source type.
func (s *Store) Sensors() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[string]string, len(s.knownSensors))
	for k, v := range s.knownSensors {
		m[k] = v
	}
	return m
}

// Len is the number of events held in memory.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Subscribe returns a channel receiving every newly added event.
func (s *Store) Subscribe() chan *model.Event {
	ch := make(chan *model.Event, 512)
	s.subMu.Lock()
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan *model.Event) {
	s.subMu.Lock()
	delete(s.subs, ch)
	s.subMu.Unlock()
	close(ch)
}
