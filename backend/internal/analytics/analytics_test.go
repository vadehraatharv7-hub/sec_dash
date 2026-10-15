package analytics

import (
	"fmt"
	"testing"
	"time"

	"sec_dash/backend/internal/model"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func ev(sec int, kind, ip, sess string, f func(*model.Event)) *model.Event {
	e := &model.Event{Time: t0.Add(time.Duration(sec) * time.Second), Kind: kind, IP: ip, Session: sess, Sensor: "s1", Source: "cowrie", Proto: "ssh", DstPort: 22}
	if f != nil {
		f(e)
	}
	return e
}

func TestSessionOutcomesAndAttackerClass(t *testing.T) {
	evs := []*model.Event{
		ev(0, model.KindConnect, "198.51.100.1", "scan", nil),
		ev(0, model.KindLoginFailed, "198.51.100.2", "brute", func(e *model.Event) { e.User, e.Pass = "root", "a" }),
		ev(1, model.KindLoginSuccess, "198.51.100.3", "intr", func(e *model.Event) { e.User, e.Pass = "root", "root" }),
		ev(2, model.KindCommand, "198.51.100.3", "intr", func(e *model.Event) { e.Input = "uname -a" }),
		ev(0, model.KindLoginSuccess, "198.51.100.4", "mal", func(e *model.Event) { e.User = "root" }),
		ev(1, model.KindDownload, "198.51.100.4", "mal", func(e *model.Event) { e.URL, e.SHA256 = "http://x/y", "aa" }),
	}
	ds := Build(Params{Range: "all"}, time.Time{}, time.Time{}, evs)
	want := map[string]string{"scan": "scan", "brute": "brute_force", "intr": "intrusion", "mal": "malware"}
	for id, outcome := range want {
		if s := ds.Session(id); s == nil || s.Outcome != outcome {
			t.Errorf("session %s: got %+v, want outcome %s", id, s, outcome)
		}
	}
	classes := map[string]string{"198.51.100.1": "scanner", "198.51.100.2": "brute_forcer", "198.51.100.3": "intruder", "198.51.100.4": "malware_dropper"}
	for ip, c := range classes {
		if a := ds.Attacker(ip); a == nil || a.Class != c {
			t.Errorf("attacker %s: got %+v, want class %s", ip, a, c)
		}
	}
	if ds.Attacker("198.51.100.4").Risk <= ds.Attacker("198.51.100.1").Risk {
		t.Error("malware dropper must outrank a scanner")
	}
}

func TestCampaignLinksIPsBySharedPayload(t *testing.T) {
	var evs []*model.Event
	for i, ip := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12"} {
		s := fmt.Sprintf("s%d", i)
		evs = append(evs, ev(i, model.KindLoginSuccess, ip, s, nil),
			ev(i, model.KindDownload, ip, s, func(e *model.Event) { e.URL, e.SHA256 = "http://evil/x", "deadbeef" }))
	}
	evs = append(evs, ev(9, model.KindConnect, "198.51.100.99", "lone", nil))
	ds := Build(Params{Range: "all"}, time.Time{}, time.Time{}, evs)
	cs := ds.Campaigns()
	if len(cs) != 1 || cs[0].Attackers != 3 {
		t.Fatalf("want one campaign of 3 IPs, got %+v", cs)
	}
	if ds.Attacker("198.51.100.99").Campaign != "" {
		t.Error("unrelated IP must not join the campaign")
	}
}

func TestCredentialStyleDetection(t *testing.T) {
	var evs []*model.Event
	for i := 0; i < 20; i++ { // many users, one password -> spraying
		evs = append(evs, ev(i, model.KindLoginFailed, "198.51.100.20", "sp", func(e *model.Event) { e.User, e.Pass = fmt.Sprintf("user%d", i), "Summer2026!" }))
	}
	ds := Build(Params{Range: "all"}, time.Time{}, time.Time{}, evs)
	if got := ds.Attacker("198.51.100.20").Style; got != "password spraying" {
		t.Errorf("got %q", got)
	}
}

func TestTimelineBucketsCoverRange(t *testing.T) {
	evs := []*model.Event{ev(0, model.KindConnect, "198.51.100.1", "a", nil), ev(3600, model.KindLoginFailed, "198.51.100.1", "a", nil)}
	ds := Build(Params{Range: "all"}, t0, t0.Add(2*time.Hour), evs)
	tl, bs := ds.Timeline()
	total := 0
	for _, b := range tl {
		total += b.Total
	}
	if total != 2 || bs <= 0 {
		t.Fatalf("timeline lost events: total=%d bucket=%d", total, bs)
	}
}
