package store

import (
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
