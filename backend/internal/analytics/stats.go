package analytics

import (
	"fmt"
	"sort"
	"time"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

type KPI struct {
	Value float64  `json:"value"`
	Prev  *float64 `json:"prev"`
}

type Bucket struct {
	T       int64          `json:"t"`
	Total   int            `json:"total"`
	Connect int            `json:"connect"`
	Failed  int            `json:"failed"`
	Success int            `json:"success"`
	Command int            `json:"command"`
	Malware int            `json:"malware"`
	Web     int            `json:"web"`
	Sensors map[string]int `json:"sensors,omitempty"`
}

type CountryStat struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Events    int    `json:"events"`
	Attackers int    `json:"attackers"`
}

type OrgStat struct {
	ASN       string `json:"asn"`
	Org       string `json:"org"`
	Events    int    `json:"events"`
	Attackers int    `json:"attackers"`
}

type PortStat struct {
	Port   int `json:"port"`
	Events int `json:"events"`
}

type Insight struct {
	Severity string `json:"severity"` // info | warn | critical
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	View     string `json:"view,omitempty"`
	Query    string `json:"query,omitempty"`
}

type Overview struct {
	From          time.Time      `json:"from"`
	To            time.Time      `json:"to"`
	BucketSeconds int64          `json:"bucket_seconds"`
	KPIs          map[string]KPI `json:"kpis"`
	Timeline      []Bucket       `json:"timeline"`
	Countries     []CountryStat  `json:"countries"`
	Orgs          []OrgStat      `json:"orgs"`
	Ports         []PortStat     `json:"ports"`
	Protocols     map[string]int `json:"protocols"`
	Classes       map[string]int `json:"classes"`
	Outcomes      map[string]int `json:"outcomes"`
	Heatmap       [7][24]int     `json:"heatmap"`
	TopAttackers  []*Attacker    `json:"top_attackers"`
	Insights      []Insight      `json:"insights"`
	Sensors       []string       `json:"sensors"`
}

func f(v int) float64 { return float64(v) }

func kpiSet(d *Dataset) map[string]float64 {
	m := map[string]float64{}
	var dur float64
	var withLogin, compromised int
	for _, s := range d.Sessions {
		if s.Source == "cowrie" {
			dur += s.Duration
		}
		if s.Logins > 0 {
			withLogin++
			if s.Success > 0 {
				compromised++
			}
		}
	}
	nCow := 0
	for _, s := range d.Sessions {
		if s.Source == "cowrie" {
			nCow++
		}
	}
	for _, e := range d.Events {
		switch e.Kind {
		case model.KindLoginFailed:
			m["login_failed"]++
		case model.KindLoginSuccess:
			m["login_success"]++
		case model.KindCommand:
			m["commands"]++
		case model.KindDownload, model.KindUpload:
			m["downloads"]++
		case model.KindHTTP:
			m["web_requests"]++
		}
	}
	m["events"] = f(len(d.Events))
	m["sessions"] = f(len(d.Sessions))
	m["attackers"] = f(len(d.Attackers))
	m["campaigns"] = f(len(d.campaigns))
	if nCow > 0 {
		m["avg_session_seconds"] = dur / float64(nCow)
	}
	if withLogin > 0 {
		m["compromise_rate"] = float64(compromised) / float64(withLogin) * 100
	}
	crit := 0
	for _, a := range d.Attackers {
		if a.RiskLabel == "critical" || a.RiskLabel == "high" {
			crit++
		}
	}
	m["high_risk_attackers"] = f(crit)
	return m
}

var niceBuckets = []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

func pickBucket(span time.Duration) time.Duration {
	for _, b := range niceBuckets {
		if span/b <= 72 {
			return b
		}
	}
	return niceBuckets[len(niceBuckets)-1]
}

// Window returns the effective [from,to) of the dataset (resolving "all").
func (d *Dataset) Window() (time.Time, time.Time) {
	from, to := d.From, d.To
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		if len(d.Events) > 0 {
			from = d.Events[0].Time
		} else {
			from = to.Add(-24 * time.Hour)
		}
	}
	return from, to
}

func (d *Dataset) Timeline() ([]Bucket, int64) {
	from, to := d.Window()
	bs := pickBucket(to.Sub(from))
	start := from.Truncate(bs)
	n := int(to.Sub(start)/bs) + 1
	if n < 1 {
		n = 1
	}
	out := make([]Bucket, n)
	for i := range out {
		out[i].T = start.Add(time.Duration(i) * bs).Unix()
	}
	for _, e := range d.Events {
		i := int(e.Time.Sub(start) / bs)
		if i < 0 || i >= n {
			continue
		}
		b := &out[i]
		b.Total++
		switch e.Kind {
		case model.KindConnect:
			b.Connect++
		case model.KindLoginFailed:
			b.Failed++
		case model.KindLoginSuccess:
			b.Success++
		case model.KindCommand:
			b.Command++
		case model.KindDownload, model.KindUpload:
			b.Malware++
		case model.KindHTTP:
			b.Web++
		}
		if b.Sensors == nil {
			b.Sensors = map[string]int{}
		}
		b.Sensors[e.Sensor]++
	}
	return out, int64(bs.Seconds())
}

func (d *Dataset) Countries(limit int) []CountryStat {
	type acc struct {
		name string
		ev   int
		ips  map[string]bool
	}
	m := map[string]*acc{}
	for _, e := range d.Events {
		if e.Geo.CountryCode == "" {
			continue
		}
		a := m[e.Geo.CountryCode]
		if a == nil {
			a = &acc{name: e.Geo.CountryName, ips: map[string]bool{}}
			m[e.Geo.CountryCode] = a
		}
		a.ev++
		a.ips[e.IP] = true
	}
	out := make([]CountryStat, 0, len(m))
	for code, a := range m {
		out = append(out, CountryStat{code, a.name, a.ev, len(a.ips)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Events > out[j].Events })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (d *Dataset) Orgs(limit int) []OrgStat {
	type acc struct {
		org string
		ev  int
		ips map[string]bool
	}
	m := map[string]*acc{}
	for _, e := range d.Events {
		if e.Geo.ASN == "" {
			continue
		}
		a := m[e.Geo.ASN]
		if a == nil {
			a = &acc{org: e.Geo.Org, ips: map[string]bool{}}
			m[e.Geo.ASN] = a
		}
		a.ev++
		a.ips[e.IP] = true
	}
	out := make([]OrgStat, 0, len(m))
	for asn, a := range m {
		out = append(out, OrgStat{asn, a.org, a.ev, len(a.ips)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Events > out[j].Events })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (d *Dataset) Ports(limit int) []PortStat {
	m := map[int]int{}
	for _, e := range d.Events {
		if e.DstPort != 0 {
			m[e.DstPort]++
		}
	}
	out := make([]PortStat, 0, len(m))
	for p, c := range m {
		out = append(out, PortStat{p, c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Events > out[j].Events })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// BuildOverview assembles the command-center payload.
func BuildOverview(d, prev *Dataset, sensors []string) *Overview {
	from, to := d.Window()
	tl, bs := d.Timeline()
	o := &Overview{From: from, To: to, BucketSeconds: bs, Timeline: tl, KPIs: map[string]KPI{},
		Countries: d.Countries(12), Orgs: d.Orgs(10), Ports: d.Ports(10), Sensors: sensors,
		Protocols: map[string]int{}, Classes: map[string]int{}, Outcomes: map[string]int{}}
	cur := kpiSet(d)
	var pv map[string]float64
	if prev != nil {
		pv = kpiSet(prev)
	}
	for k, v := range cur {
		kp := KPI{Value: v}
		if pv != nil {
			p := pv[k]
			kp.Prev = &p
		}
		o.KPIs[k] = kp
	}
	for _, k := range []string{"login_failed", "login_success", "commands", "downloads", "web_requests", "campaigns",
		"avg_session_seconds", "compromise_rate", "high_risk_attackers"} {
		if _, ok := o.KPIs[k]; !ok {
			kp := KPI{}
			if pv != nil {
				p := pv[k]
				kp.Prev = &p
			}
			o.KPIs[k] = kp
		}
	}
	for _, e := range d.Events {
		o.Protocols[e.Proto]++
		wd := int(e.Time.Weekday())
		o.Heatmap[wd][e.Time.Hour()]++
	}
	for _, a := range d.Attackers {
		o.Classes[a.Class]++
	}
	for _, s := range d.Sessions {
		o.Outcomes[s.Outcome]++
	}
	n := 8
	if len(d.Attackers) < n {
		n = len(d.Attackers)
	}
	o.TopAttackers = append([]*Attacker{}, d.Attackers[:n]...)
	o.Insights = d.Insights(tl)
	return o
}

// ---- insights --------------------------------------------------------------

func (d *Dataset) Insights(tl []Bucket) []Insight {
	var out []Insight
	// compromised sessions
	succ := map[string]int{}
	nSucc := 0
	for _, e := range d.Events {
		if e.Kind == model.KindLoginSuccess {
			nSucc++
			succ[e.User]++
		}
	}
	if nSucc > 0 {
		top, tc := topKey(succ)
		out = append(out, Insight{"critical", fmt.Sprintf("%d attackers authenticated successfully", countSuccessIPs(d)),
			fmt.Sprintf("%d successful logins; most used account: %q (%d times).", nSucc, top, tc), "sessions", "outcome=intrusion"})
	}
	// malware
	hashes := map[string]bool{}
	for _, e := range d.Events {
		if e.SHA256 != "" && (e.Kind == model.KindDownload || e.Kind == model.KindUpload) {
			hashes[e.SHA256] = true
		}
	}
	if len(hashes) > 0 {
		out = append(out, Insight{"critical", fmt.Sprintf("%d unique malware samples captured", len(hashes)),
			"Payloads were downloaded into the honeypot. Review hashes and distribution URLs.", "malware", ""})
	}
	// campaigns
	if len(d.campaigns) > 0 {
		c := d.campaigns[0]
		out = append(out, Insight{"warn", fmt.Sprintf("%d coordinated campaign(s) detected", len(d.campaigns)),
			fmt.Sprintf("Largest: %q with %d IPs across %d countries, linked by %v.", c.Name, c.Attackers, len(c.Countries), c.SharedBasis), "campaigns", ""})
	}
	// credential style
	styles := map[string]int{}
	for _, a := range d.Attackers {
		if a.Style == "password spraying" || a.Style == "credential stuffing" {
			styles[a.Style]++
		}
	}
	for st, n := range styles {
		out = append(out, Insight{"warn", fmt.Sprintf("%d IPs performing %s", n, st),
			"These sources rotate many accounts/passwords - likely automated credential attacks.", "credentials", ""})
	}
	// web exploits
	labels := map[string]int{}
	for _, e := range d.Events {
		if e.Kind == model.KindHTTP {
			l, t := intel.ClassifyWeb(e.Path)
			if t.ID == "T1190" {
				labels[l]++
			}
		}
	}
	if len(labels) > 0 {
		l, c := topKey(labels)
		out = append(out, Insight{"warn", fmt.Sprintf("Web exploit attempts: %s", l),
			fmt.Sprintf("%d request(s) matched exploit signatures on the web honeypot.", c), "events", "kind=http_request"})
	}
	// traffic spike
	if len(tl) >= 8 {
		last := tl[len(tl)-1]
		if len(tl) > 1 {
			last = tl[len(tl)-2] // last complete bucket
		}
		var vals []int
		for _, b := range tl[:len(tl)-2] {
			vals = append(vals, b.Total)
		}
		sort.Ints(vals)
		if len(vals) > 0 {
			med := vals[len(vals)/2]
			if med > 0 && last.Total >= med*4 && last.Total >= 20 {
				out = append(out, Insight{"warn", "Traffic spike",
					fmt.Sprintf("Latest interval saw %d events, %dx the median (%d).", last.Total, last.Total/med, med), "events", ""})
			}
		}
	}
	if len(d.Attackers) > 0 {
		a := d.Attackers[0]
		if a.Risk >= 60 {
			loc := a.Geo.CountryName
			if loc == "" {
				loc = "unknown location"
			}
			out = append(out, Insight{"info", fmt.Sprintf("Top threat: %s (%s)", a.IP, loc),
				fmt.Sprintf("Risk %d (%s), %d sessions, class %s.", a.Risk, a.RiskLabel, a.Sessions, a.Class), "attackers", "ip=" + a.IP})
		}
	}
	if len(out) == 0 {
		out = append(out, Insight{"info", "No notable activity", "Nothing above background-noise level in this window.", "", ""})
	}
	return out
}

func topKey(m map[string]int) (string, int) {
	best, bc := "", -1
	for k, v := range m {
		if v > bc || (v == bc && k < best) {
			best, bc = k, v
		}
	}
	return best, bc
}

func countSuccessIPs(d *Dataset) int {
	n := 0
	for _, a := range d.Attackers {
		if a.Success > 0 {
			n++
		}
	}
	return n
}

// ---- geo -------------------------------------------------------------------

type GeoPoint struct {
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Country   string  `json:"country"`
	Code      string  `json:"code"`
	City      string  `json:"city"`
	Attackers int     `json:"attackers"`
	Events    int     `json:"events"`
	MaxRisk   int     `json:"max_risk"`
	TopIP     string  `json:"top_ip"`
}

func (d *Dataset) GeoPoints() []GeoPoint {
	type key struct{ la, lo int }
	m := map[key]*GeoPoint{}
	for _, a := range d.Attackers {
		g := a.Geo
		if g.CountryCode == "" || (g.Latitude == 0 && g.Longitude == 0) {
			continue
		}
		k := key{int(g.Latitude * 10), int(g.Longitude * 10)}
		p := m[k]
		if p == nil {
			p = &GeoPoint{Lat: g.Latitude, Lon: g.Longitude, Country: g.CountryName, Code: g.CountryCode, City: g.City}
			m[k] = p
		}
		p.Attackers++
		p.Events += a.Events
		if a.Risk >= p.MaxRisk {
			p.MaxRisk, p.TopIP = a.Risk, a.IP
		}
	}
	out := make([]GeoPoint, 0, len(m))
	for _, p := range m {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Events > out[j].Events })
	return out
}
