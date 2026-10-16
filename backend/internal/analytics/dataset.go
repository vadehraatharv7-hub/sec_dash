// Package analytics derives sessions, attackers, campaigns and statistics from
// the normalized event stream.
package analytics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

// Params selects the slice of data to analyze.
type Params struct {
	Range  string // 1h 6h 24h 7d 30d all
	Sensor string // "" / "all" / sensor id
}

func (p Params) Key() string { return p.Range + "|" + p.Sensor }

// Duration of the range; 0 means unbounded.
func RangeDuration(r string) time.Duration {
	switch r {
	case "1h":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "24h", "":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	}
	return 0
}

// Session is one reconstructed attacker interaction.
type Session struct {
	ID          string            `json:"id"`
	IP          string            `json:"src_ip"`
	Sensor      string            `json:"sensor"`
	Source      string            `json:"source"`
	Proto       string            `json:"protocol"`
	DstPort     int               `json:"dst_port"`
	Start       time.Time         `json:"start"`
	End         time.Time         `json:"end"`
	Duration    float64           `json:"duration"`
	Events      int               `json:"events"`
	Logins      int               `json:"logins"`
	Failed      int               `json:"failed"`
	Success     int               `json:"success"`
	Commands    int               `json:"commands"`
	Downloads   int               `json:"downloads"`
	Requests    int               `json:"requests"`
	Client      string            `json:"client,omitempty"`
	Outcome     string            `json:"outcome"`
	Severity    int               `json:"severity"`
	Techniques  []intel.Technique `json:"techniques"`
	Families    []string          `json:"families,omitempty"`
	Geo         model.Geo         `json:"geo"`
	Username    string            `json:"username,omitempty"` // account that succeeded, if any
	Fingerprint string            `json:"fingerprint,omitempty"`

	evs []*model.Event
}

// Attacker aggregates everything seen from one source IP.
type Attacker struct {
	IP         string            `json:"ip"`
	Geo        model.Geo         `json:"geo"`
	First      time.Time         `json:"first_seen"`
	Last       time.Time         `json:"last_seen"`
	Events     int               `json:"events"`
	Sessions   int               `json:"sessions"`
	Failed     int               `json:"failed_logins"`
	Success    int               `json:"successful_logins"`
	Commands   int               `json:"commands"`
	Downloads  int               `json:"downloads"`
	Requests   int               `json:"web_requests"`
	Users      int               `json:"distinct_users"`
	Passwords  int               `json:"distinct_passwords"`
	Style      string            `json:"credential_style,omitempty"`
	Class      string            `json:"class"`
	Risk       int               `json:"risk"`
	RiskLabel  string            `json:"risk_label"`
	Sensors    []string          `json:"sensors"`
	Ports      []int             `json:"ports"`
	Clients    []string          `json:"clients,omitempty"`
	Techniques []intel.Technique `json:"techniques"`
	Families   []string          `json:"families,omitempty"`
	Campaign   string            `json:"campaign,omitempty"`

	users, pwds map[string]bool
	sens        map[string]bool
	ports       map[int]bool
	clients     map[string]bool
	tech        map[string]intel.Technique
	fams        map[string]bool
	sessIDs     []string
}

// Dataset is a fully derived view over a time range + sensor selection.
type Dataset struct {
	P         Params
	From, To  time.Time
	Events    []*model.Event
	Sessions  []*Session
	Attackers []*Attacker

	sessByID map[string]*Session
	attByIP  map[string]*Attacker
	Built    time.Time

	campaigns []*Campaign
}

func (d *Dataset) Session(id string) *Session   { return d.sessByID[id] }
func (d *Dataset) Attacker(ip string) *Attacker { return d.attByIP[ip] }

// Build derives sessions and attackers from an event slice.
func Build(p Params, from, to time.Time, evs []*model.Event) *Dataset {
	evs = mergeMultiline(evs)
	d := &Dataset{P: p, From: from, To: to, Events: evs, sessByID: map[string]*Session{},
		attByIP: map[string]*Attacker{}, Built: time.Now()}
	d.buildSessions()
	d.buildAttackers()
	d.buildCampaigns()
	return d
}

const webGap = 30 * time.Minute

func (d *Dataset) buildSessions() {
	groups := map[string][]*model.Event{}
	var order []string
	lastWeb := map[string]struct {
		key string
		t   time.Time
	}{}
	for _, e := range d.Events {
		key := e.Session
		if key == "" {
			who := e.IP
			if who == "" {
				who = "anon-" + e.Sensor
			}
			lw := lastWeb[who]
			if lw.key == "" || e.Time.Sub(lw.t) > webGap {
				lw.key = fmt.Sprintf("web-%s-%d", who, e.Time.Unix())
			}
			lw.t = e.Time
			lastWeb[who] = lw
			key = lw.key
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], e)
	}
	for _, key := range order {
		evs := groups[key]
		s := &Session{ID: key, evs: evs, Start: evs[0].Time, End: evs[0].Time}
		creds := map[string]bool{}
		var cmds []string
		var allTechs []intel.Technique
		seenT := map[string]bool{}
		addT := func(ts ...intel.Technique) {
			for _, t := range ts {
				if !seenT[t.ID] {
					seenT[t.ID] = true
					allTechs = append(allTechs, t)
				}
			}
		}
		fams := map[string]bool{}
		webSev := 0
		for _, e := range evs {
			if s.IP == "" && e.IP != "" {
				s.IP = e.IP
				s.Geo = e.Geo
			}
			if s.Geo.CountryCode == "" && e.Geo.CountryCode != "" {
				s.Geo = e.Geo
			}
			s.Sensor, s.Source, s.Proto = e.Sensor, e.Source, e.Proto
			if e.DstPort != 0 {
				s.DstPort = e.DstPort
			}
			if e.Time.Before(s.Start) {
				s.Start = e.Time
			}
			if e.Time.After(s.End) {
				s.End = e.Time
			}
			s.Events++
			switch e.Kind {
			case model.KindLoginFailed:
				s.Failed++
				s.Logins++
				creds[e.User+":"+e.Pass] = true
			case model.KindLoginSuccess:
				s.Success++
				s.Logins++
				creds[e.User+":"+e.Pass] = true
				if s.Username == "" {
					s.Username = e.User
				}
			case model.KindCommand:
				s.Commands++
				cmds = append(cmds, intel.NormalizeCommand(e.Input))
				_, ts := intel.ClassifyCommand(e.Input)
				addT(ts...)
				if f := intel.FamilyOf(e.Input); f != "" {
					fams[f] = true
				}
			case model.KindDownload, model.KindUpload:
				s.Downloads++
				addT(intel.T1105)
				if f := intel.FamilyOf(e.URL); f != "" {
					fams[f] = true
				}
			case model.KindHTTP:
				s.Requests++
				label, t := intel.ClassifyWeb(e.Path)
				addT(t)
				if t.ID == "T1190" {
					webSev = 40
				} else if webSev < 15 {
					webSev = 15
				}
				if f := intel.FamilyOf(e.Path); f != "" {
					fams[f] = true
				}
				_ = label
			case model.KindClientVersion:
				s.Client = e.Client
			case model.KindClose:
				if e.Duration > 0 {
					s.Duration = e.Duration
				}
			}
			if e.Client != "" && s.Client == "" {
				s.Client = e.Client
			}
		}
		if s.Duration == 0 {
			s.Duration = s.End.Sub(s.Start).Seconds()
		}
		if s.Failed > 0 {
			if len(creds) >= 10 {
				addT(intel.T1110_4)
			} else {
				addT(intel.T1110_1)
			}
		}
		if s.Success > 0 {
			addT(intel.T1078)
		}
		if s.Source == "cowrie" && len(allTechs) == 0 {
			addT(intel.T1595)
		}
		intel.SortTechniques(allTechs)
		if allTechs == nil {
			allTechs = []intel.Technique{}
		}
		s.Techniques = allTechs
		for f := range fams {
			s.Families = append(s.Families, f)
		}
		sort.Strings(s.Families)
		if len(cmds) >= 2 {
			s.Fingerprint = hash8(strings.Join(cmds, "\n"))
		}

		switch {
		case s.Source == "snare":
			s.Outcome = "web"
			s.Severity = 8 + webSev
		case s.Downloads > 0:
			s.Outcome = "malware"
			s.Severity = 85
		case s.Commands > 0:
			s.Outcome = "intrusion"
			s.Severity = minInt(80, 60+s.Commands*2)
		case s.Success > 0:
			s.Outcome = "login_only"
			s.Severity = 45
		case s.Failed > 0:
			s.Outcome = "brute_force"
			s.Severity = 15 + minInt(10, s.Failed/5)
		default:
			s.Outcome = "scan"
			s.Severity = 5
		}
		if len(s.Families) > 0 && s.Severity < 90 {
			s.Severity += 5
		}
		d.Sessions = append(d.Sessions, s)
		d.sessByID[s.ID] = s
	}
	sort.Slice(d.Sessions, func(i, j int) bool { return d.Sessions[i].Start.After(d.Sessions[j].Start) })
}

func (d *Dataset) buildAttackers() {
	for _, e := range d.Events {
		if e.IP == "" {
			continue
		}
		a := d.attByIP[e.IP]
		if a == nil {
			a = &Attacker{IP: e.IP, First: e.Time, Last: e.Time, users: map[string]bool{}, pwds: map[string]bool{},
				sens: map[string]bool{}, ports: map[int]bool{}, clients: map[string]bool{},
				tech: map[string]intel.Technique{}, fams: map[string]bool{}}
			d.attByIP[e.IP] = a
		}
		if a.Geo.CountryCode == "" {
			a.Geo = e.Geo
		}
		if e.Time.Before(a.First) {
			a.First = e.Time
		}
		if e.Time.After(a.Last) {
			a.Last = e.Time
		}
		a.Events++
		a.sens[e.Sensor] = true
		if e.DstPort != 0 {
			a.ports[e.DstPort] = true
		}
		switch e.Kind {
		case model.KindLoginFailed:
			a.Failed++
		case model.KindLoginSuccess:
			a.Success++
		case model.KindCommand:
			a.Commands++
		case model.KindDownload, model.KindUpload:
			a.Downloads++
		case model.KindHTTP:
			a.Requests++
		}
		if e.Kind == model.KindLoginFailed || e.Kind == model.KindLoginSuccess {
			a.users[e.User] = true
			a.pwds[e.Pass] = true
		}
		if e.Client != "" {
			a.clients[e.Client] = true
		}
	}
	for _, s := range d.Sessions {
		a := d.attByIP[s.IP]
		if a == nil {
			continue
		}
		a.Sessions++
		a.sessIDs = append(a.sessIDs, s.ID)
		for _, t := range s.Techniques {
			a.tech[t.ID] = t
		}
		for _, f := range s.Families {
			a.fams[f] = true
		}
	}
	for _, a := range d.Attackers0() {
		a.Users, a.Passwords = len(a.users), len(a.pwds)
		tries := a.Failed + a.Success
		switch {
		case tries < 3:
		case a.Passwords >= 15 && a.Users >= 15:
			a.Style = "credential stuffing"
		case a.Users >= 8 && a.Passwords <= 3:
			a.Style = "password spraying"
		case a.Passwords >= 8 && a.Users <= 3:
			a.Style = "dictionary brute force"
		case a.Passwords >= 8 || a.Users >= 8:
			a.Style = "mixed guessing"
		default:
			a.Style = "low-volume guessing"
		}
		a.Sensors = sortedKeys(a.sens)
		a.Ports, a.Techniques = []int{}, []intel.Technique{}
		for p := range a.ports {
			a.Ports = append(a.Ports, p)
		}
		sort.Ints(a.Ports)
		a.Clients = sortedKeys(a.clients)
		for _, t := range a.tech {
			a.Techniques = append(a.Techniques, t)
		}
		intel.SortTechniques(a.Techniques)
		a.Families = sortedKeys(a.fams)
		a.classifyAndScore(d)
		d.Attackers = append(d.Attackers, a)
	}
	sort.Slice(d.Attackers, func(i, j int) bool {
		if d.Attackers[i].Risk != d.Attackers[j].Risk {
			return d.Attackers[i].Risk > d.Attackers[j].Risk
		}
		return d.Attackers[i].Events > d.Attackers[j].Events
	})
}

// Attackers0 returns the raw map values in deterministic order.
func (d *Dataset) Attackers0() []*Attacker {
	ips := make([]string, 0, len(d.attByIP))
	for ip := range d.attByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]*Attacker, len(ips))
	for i, ip := range ips {
		out[i] = d.attByIP[ip]
	}
	return out
}

func (a *Attacker) classifyAndScore(d *Dataset) {
	exploit := false
	for _, id := range a.sessIDs {
		s := d.sessByID[id]
		if s.Source == "snare" && s.Severity >= 40 {
			exploit = true
		}
	}
	base := 5
	switch {
	case a.Downloads > 0:
		a.Class, base = "malware_dropper", 80
	case a.Commands > 0:
		a.Class, base = "intruder", 65
	case a.Success > 0:
		a.Class, base = "compromiser", 50
	case exploit:
		a.Class, base = "web_exploiter", 35
	case a.Failed > 0:
		a.Class, base = "brute_forcer", 20
	case a.Requests > 0:
		a.Class, base = "web_recon", 12
	default:
		a.Class, base = "scanner", 5
	}
	risk := float64(base)
	risk += math.Min(8, math.Log2(float64(a.Events)+1))
	for _, t := range a.Techniques {
		switch t.Tactic {
		case "Persistence", "Defense Evasion", "Impact":
			risk += 3
		}
	}
	if len(a.Sensors) > 1 {
		risk += 5
	}
	if len(a.Families) > 0 {
		risk += 5
	}
	a.Risk = int(math.Min(100, risk))
	switch {
	case a.Risk >= 80:
		a.RiskLabel = "critical"
	case a.Risk >= 60:
		a.RiskLabel = "high"
	case a.Risk >= 35:
		a.RiskLabel = "medium"
	default:
		a.RiskLabel = "low"
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// needsMore reports whether a shell line is unfinished: an unclosed quote or a
// trailing backslash. Cowrie logs every line of a pasted multi-line command as its own event.
func needsMore(s string) bool {
	single, double := 0, 0
	esc := false
	for _, r := range s {
		switch {
		case esc:
			esc = false
		case r == '\\':
			esc = true
		case r == '\'':
			single++
		case r == '"':
			double++
		}
	}
	return single%2 == 1 || double%2 == 1 || strings.HasSuffix(strings.TrimRight(s, " \t"), "\\")
}

// mergeMultiline joins the lines of one pasted command back into a single command
// event (kept at its first line's timestamp). Other events pass through unchanged.
func mergeMultiline(in []*model.Event) []*model.Event {
	const maxGap = 5 * time.Second
	out := make([]*model.Event, 0, len(in))
	open := map[string]*model.Event{}
	last := map[string]time.Time{}
	for _, e := range in {
		if e.Kind == model.KindCommand && e.Session != "" {
			if p := open[e.Session]; p != nil && e.Time.Sub(last[e.Session]) <= maxGap {
				p.Input += "\n" + e.Input
				last[e.Session] = e.Time
				if !needsMore(p.Input) {
					delete(open, e.Session)
				}
				continue
			}
			delete(open, e.Session)
			if needsMore(e.Input) {
				cp := *e // never modify the stored event
				open[e.Session], last[e.Session] = &cp, e.Time
				out = append(out, &cp)
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
