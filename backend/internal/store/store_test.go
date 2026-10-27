package store

import (
	"errors"
	"testing"
	"time"

	"sec_dash/backend/internal/model"
)

func ev(ms int, input string) *model.Event {
	return &model.Event{Time: time.Unix(0, 0).Add(time.Duration(ms) * time.Millisecond), Sensor: "s", Source: "cowrie", Kind: model.KindCommand,
		RawType: "cowrie.command.input", Session: "a", IP: "198.51.100.1", Input: input}
}

func TestAddDropsResentEvents(t *testing.T) {
	s := New(NewMemory(), 1000)
	s.Add([]*model.Event{ev(1, "sh"), ev(2, "shell")}, false)
	// the same batch arrives again (a retry), plus one genuinely new event
	s.Add([]*model.Event{ev(1, "sh"), ev(2, "shell"), ev(3, "enable")}, false)
	if got := s.Len(); got != 3 {
		t.Fatalf("expected 3 distinct events, have %d", got)
	}
}

type dupLoader struct{ *Memory }

func (d dupLoader) Load(int) ([]*model.Event, error) {
	return []*model.Event{ev(1, "sh"), ev(1, "sh"), ev(1, "sh"), ev(1, "sh"), ev(2, "x")}, nil
}

func TestLoadIgnoresDuplicatesAlreadyInTheDatabase(t *testing.T) {
	s := New(dupLoader{NewMemory()}, 1000)
	if s.Len() != 2 {
		t.Fatalf("four stored copies must load as one event, have %d events", s.Len())
	}
}

// flaky fails its first n inserts, like a database that is throttling.
type flaky struct {
	*Memory
	fails int
	saved int
}

func (f *flaky) Insert(evs []*model.Event) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("429 too many requests")
	}
	f.saved += len(evs)
	return nil
}

func TestFailedPersistStoresNothingAndTheSameBatchCanBeResent(t *testing.T) {
	p := &flaky{Memory: NewMemory(), fails: 2}
	s := New(p, 1000)
	batch := []*model.Event{ev(1, "sh"), ev(2, "shell")}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := s.Add(batch, true); err == nil {
			t.Fatalf("attempt %d: the database is failing, Add must report it", attempt)
		}
		if s.Len() != 0 {
			t.Fatalf("attempt %d: events must not become visible before they are saved", attempt)
		}
	}
	// the database recovers: the SAME batch must now go through, which is what a sensor retry sends
	if err := s.Add(batch, true); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 || p.saved != 2 {
		t.Fatalf("after recovery want 2 stored, have memory=%d saved=%d", s.Len(), p.saved)
	}
	// and a duplicate resend after success changes nothing
	if err := s.Add(batch, true); err != nil || s.Len() != 2 || p.saved != 2 {
		t.Fatalf("a resent batch must be ignored (err=%v memory=%d saved=%d)", err, s.Len(), p.saved)
	}
}

func TestDuplicatesInsideOneBatchAreStoredOnce(t *testing.T) {
	p := &flaky{Memory: NewMemory()}
	s := New(p, 1000)
	if err := s.Add([]*model.Event{ev(1, "sh"), ev(1, "sh"), ev(1, "sh")}, true); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 || p.saved != 1 {
		t.Fatalf("want one event, have memory=%d saved=%d", s.Len(), p.saved)
	}
}
