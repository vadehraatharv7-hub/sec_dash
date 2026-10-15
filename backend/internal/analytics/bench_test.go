package analytics

import (
	"fmt"
	"testing"
	"time"

	"sec_dash/backend/internal/model"
)

func synth(n int) []*model.Event {
	evs := make([]*model.Event, 0, n)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; len(evs) < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65025)%250, (i/255)%255, i%255+1)
		sess := fmt.Sprintf("s%d", i)
		t := base.Add(time.Duration(i) * time.Second)
		evs = append(evs, &model.Event{Time: t, Kind: model.KindConnect, IP: ip, Session: sess, Sensor: "a", Source: "cowrie"})
		for j := 0; j < 6; j++ {
			evs = append(evs, &model.Event{Time: t, Kind: model.KindLoginFailed, IP: ip, Session: sess, Sensor: "a", Source: "cowrie", User: "root", Pass: fmt.Sprint(j)})
		}
		evs = append(evs, &model.Event{Time: t, Kind: model.KindCommand, IP: ip, Session: sess, Sensor: "a", Source: "cowrie", Input: "uname -a"})
	}
	return evs
}

func BenchmarkBuild250k(b *testing.B) {
	evs := synth(250000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Build(Params{Range: "all"}, time.Time{}, time.Time{}, evs)
	}
}
