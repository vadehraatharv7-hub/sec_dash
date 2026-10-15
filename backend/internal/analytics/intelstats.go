package analytics

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

// ---- credentials -----------------------------------------------------------

var defaultCreds = map[string]bool{
	"root:root": true, "root:admin": true, "root:123456": true, "root:password": true, "root:toor": true,
	"root:1234": true, "root:12345": true, "root:": true, "admin:admin": true, "admin:123456": true,
	"admin:password": true, "admin:1234": true, "admin:": true, "user:user": true, "pi:raspberry": true,
	"ubnt:ubnt": true, "test:test": true, "ubuntu:ubuntu": true, "oracle:oracle": true, "postgres:postgres": true,
	"guest:guest": true, "support:support": true, "default:default": true, "admin:admin123": true,
}

type CredStat struct {
	Value   string `json:"value"`
	Count   int    `json:"count"`
	IPs     int    `json:"ips"`
	Success int    `json:"success"`
}

type PairStat struct {
	User    string    `json:"username"`
	Pass    string    `json:"password"`
	Count   int       `json:"count"`
	IPs     int       `json:"ips"`
	Success int       `json:"success"`
	Default bool      `json:"is_default"`
	Last    time.Time `json:"last_seen"`
}

type LenBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type Credentials struct {
	Attempts        int            `json:"attempts"`
	UniquePairs     int            `json:"unique_pairs"`
	UniqueUsers     int            `json:"unique_users"`
	UniquePasswords int            `json:"unique_passwords"`
	DefaultPct      float64        `json:"default_pct"`
	Usernames       []CredStat     `json:"usernames"`
	Passwords       []CredStat     `json:"passwords"`
	Pairs           []PairStat     `json:"pairs"`
	Successful      []PairStat     `json:"successful"`
	Styles          map[string]int `json:"styles"`
	Lengths         []LenBucket    `json:"password_lengths"`
	TopSources      []*Attacker    `json:"top_sources"`
}

func (d *Dataset) Credentials(limit int) *Credentials {
	type acc struct {
		n, succ int
		ips     map[string]bool
		last    time.Time
	}
	users, pwds := map[string]*acc{}, map[string]*acc{}
	pairs := map[string]*acc{}
	touch := func(m map[string]*acc, k string, e *model.Event) {
		a := m[k]
		if a == nil {
			a = &acc{ips: map[string]bool{}}
			m[k] = a
		}
		a.n++
		if e.Kind == model.KindLoginSuccess {
			a.succ++
		}
		a.ips[e.IP] = true
		if e.Time.After(a.last) {
			a.last = e.Time
		}
	}
	c := &Credentials{Styles: map[string]int{}, Usernames: []CredStat{}, Passwords: []CredStat{}, Pairs: []PairStat{},
		Successful: []PairStat{}, Lengths: []LenBucket{}, TopSources: []*Attacker{}}
	def := 0
	lens := map[string]int{}
	for _, e := range d.Events {
		if e.Kind != model.KindLoginFailed && e.Kind != model.KindLoginSuccess {
			continue
		}
		c.Attempts++
		touch(users, e.User, e)
		touch(pwds, e.Pass, e)
		touch(pairs, e.User+"\x00"+e.Pass, e)
		if defaultCreds[strings.ToLower(e.User)+":"+e.Pass] {
			def++
		}
		l := len(e.Pass)
		switch {
		case l == 0:
			lens["empty"]++
		case l <= 4:
			lens["1-4"]++
		case l <= 6:
			lens["5-6"]++
		case l <= 8:
			lens["7-8"]++
		case l <= 12:
			lens["9-12"]++
		default:
			lens["13+"]++
		}
	}
	if c.Attempts > 0 {
		c.DefaultPct = float64(def) / float64(c.Attempts) * 100
	}
	c.UniquePairs, c.UniqueUsers, c.UniquePasswords = len(pairs), len(users), len(pwds)
	conv := func(m map[string]*acc) []CredStat {
		out := make([]CredStat, 0, len(m))
		for k, a := range m {
			out = append(out, CredStat{k, a.n, len(a.ips), a.succ})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].Value < out[j].Value
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return out
	}
	c.Usernames, c.Passwords = conv(users), conv(pwds)
	if c.Usernames == nil {
		c.Usernames = []CredStat{}
	}
	if c.Passwords == nil {
		c.Passwords = []CredStat{}
	}
	for k, a := range pairs {
		u, p, _ := strings.Cut(k, "\x00")
		ps := PairStat{u, p, a.n, len(a.ips), a.succ, defaultCreds[strings.ToLower(u)+":"+p], a.last}
		c.Pairs = append(c.Pairs, ps)
		if a.succ > 0 {
			c.Successful = append(c.Successful, ps)
		}
	}
	sort.Slice(c.Pairs, func(i, j int) bool { return c.Pairs[i].Count > c.Pairs[j].Count })
	sort.Slice(c.Successful, func(i, j int) bool { return c.Successful[i].Success > c.Successful[j].Success })
	if limit > 0 && len(c.Pairs) > limit {
		c.Pairs = c.Pairs[:limit]
	}
	if len(c.Successful) > limit && limit > 0 {
		c.Successful = c.Successful[:limit]
	}
	for _, l := range []string{"empty", "1-4", "5-6", "7-8", "9-12", "13+"} {
		c.Lengths = append(c.Lengths, LenBucket{l, lens[l]})
	}
	for _, a := range d.Attackers {
		if a.Style != "" {
			c.Styles[a.Style]++
			if len(c.TopSources) < 8 && a.Failed+a.Success >= 10 {
				c.TopSources = append(c.TopSources, a)
			}
		}
	}
	sort.Slice(c.TopSources, func(i, j int) bool {
		return c.TopSources[i].Failed+c.TopSources[i].Success > c.TopSources[j].Failed+c.TopSources[j].Success
	})
	return c
}

// ---- commands --------------------------------------------------------------

type CmdStat struct {
	Command    string            `json:"command"`
	Sample     string            `json:"sample"`
	Count      int               `json:"count"`
	Sessions   int               `json:"sessions"`
	IPs        int               `json:"ips"`
	Category   string            `json:"category"`
	Categories []string          `json:"categories"`
	Techniques []intel.Technique `json:"techniques"`
	First      time.Time         `json:"first_seen"`
	Last       time.Time         `json:"last_seen"`
}

type Commands struct {
	Total      int            `json:"total"`
	Unique     int            `json:"unique"`
	Top        []CmdStat      `json:"top"`
	Categories map[string]int `json:"categories"`
	Playbooks  []Playbook     `json:"playbooks"`
}

func (d *Dataset) Commands(limit int) *Commands {
	type acc struct {
		sample string
		n      int
		sess   map[string]bool
		ips    map[string]bool
		first  time.Time
		last   time.Time
	}
	m := map[string]*acc{}
	out := &Commands{Categories: map[string]int{}, Top: []CmdStat{}, Playbooks: []Playbook{}}
	for _, e := range d.Events {
		if e.Kind != model.KindCommand {
			continue
		}
		out.Total++
		k := intel.NormalizeCommand(e.Input)
		a := m[k]
		if a == nil {
			a = &acc{sample: e.Input, sess: map[string]bool{}, ips: map[string]bool{}, first: e.Time}
			m[k] = a
		}
		a.n++
		a.sess[e.Session] = true
		a.ips[e.IP] = true
		a.last = e.Time
	}
	out.Unique = len(m)
	for k, a := range m {
		cats, techs := intel.ClassifyCommand(a.sample)
		out.Categories[intel.PrimaryCategory(cats)] += a.n
		out.Top = append(out.Top, CmdStat{k, a.sample, a.n, len(a.sess), len(a.ips), intel.PrimaryCategory(cats), cats, techs, a.first, a.last})
	}
	sort.Slice(out.Top, func(i, j int) bool {
		if out.Top[i].Count != out.Top[j].Count {
			return out.Top[i].Count > out.Top[j].Count
		}
		return out.Top[i].Command < out.Top[j].Command
	})
	if limit > 0 && len(out.Top) > limit {
		out.Top = out.Top[:limit]
	}
	// global playbooks
	type pb struct {
		p   Playbook
		ips map[string]bool
	}
	pbs := map[string]*pb{}
	for _, s := range d.Sessions {
		if s.Fingerprint == "" {
			continue
		}
		x := pbs[s.Fingerprint]
		if x == nil {
			x = &pb{p: Playbook{Hash: s.Fingerprint}, ips: map[string]bool{}}
			for _, e := range s.evs {
				if e.Kind == model.KindCommand && len(x.p.Commands) < 15 {
					x.p.Commands = append(x.p.Commands, e.Input)
				}
			}
			pbs[s.Fingerprint] = x
		}
		x.p.Sessions++
		x.ips[s.IP] = true
	}
	for _, x := range pbs {
		x.p.IPs = len(x.ips)
		out.Playbooks = append(out.Playbooks, x.p)
	}
	sort.Slice(out.Playbooks, func(i, j int) bool { return out.Playbooks[i].Sessions > out.Playbooks[j].Sessions })
	if len(out.Playbooks) > 10 {
		out.Playbooks = out.Playbooks[:10]
	}
	return out
}

// ---- malware ---------------------------------------------------------------

var reURL = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s'"|;&<>)]+`)

type Sample struct {
	SHA256   string    `json:"sha256"`
	URLs     []string  `json:"urls"`
	Size     int64     `json:"size"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
	Sessions int       `json:"sessions"`
	IPs      []string  `json:"ips"`
	Sensors  []string  `json:"sensors"`
	Family   string    `json:"family,omitempty"`
	Campaign string    `json:"campaign,omitempty"`
}

type URLStat struct {
	URL      string    `json:"url"`
	Host     string    `json:"host"`
	Count    int       `json:"count"`
	IPs      int       `json:"ips"`
	Captured bool      `json:"captured"`
	SHA256   string    `json:"sha256,omitempty"`
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
}

type Malware struct {
	Samples []Sample   `json:"samples"`
	URLs    []URLStat  `json:"urls"`
	Hosts   []CredStat `json:"hosts"`
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return ""
	}
	return strings.ToLower(p.Hostname())
}

func (d *Dataset) Malware() *Malware {
	samples := map[string]*Sample{}
	sets := map[string]map[string]map[string]bool{} // hash -> {urls, ips, sensors, sessions}
	urls := map[string]*URLStat{}
	urlIPs := map[string]map[string]bool{}
	urlHash := map[string]string{}
	note := func(u string, e *model.Event, captured bool, sha string) {
		x := urls[u]
		if x == nil {
			x = &URLStat{URL: u, Host: hostOf(u), First: e.Time}
			urls[u] = x
			urlIPs[u] = map[string]bool{}
		}
		x.Count++
		x.Last = e.Time
		if captured {
			x.Captured = true
		}
		if sha != "" {
			x.SHA256 = sha
		}
		urlIPs[u][e.IP] = true
	}
	for _, e := range d.Events {
		switch e.Kind {
		case model.KindDownload, model.KindUpload:
			if e.URL != "" {
				note(e.URL, e, e.SHA256 != "", e.SHA256)
			}
			if e.SHA256 == "" {
				continue
			}
			s := samples[e.SHA256]
			if s == nil {
				s = &Sample{SHA256: e.SHA256, First: e.Time}
				samples[e.SHA256] = s
				sets[e.SHA256] = map[string]map[string]bool{"u": {}, "i": {}, "n": {}, "s": {}}
			}
			if e.Size > s.Size {
				s.Size = e.Size
			}
			s.Last = e.Time
			if e.URL != "" {
				sets[e.SHA256]["u"][e.URL] = true
				urlHash[e.URL] = e.SHA256
				if s.Family == "" {
					s.Family = intel.FamilyOf(e.URL)
				}
			}
			sets[e.SHA256]["i"][e.IP] = true
			sets[e.SHA256]["n"][e.Sensor] = true
			sets[e.SHA256]["s"][e.Session] = true
		case model.KindCommand:
			for _, u := range reURL.FindAllString(e.Input, -1) {
				note(strings.TrimRight(u, ".,"), e, false, "")
			}
		}
	}
	out := &Malware{}
	for h, s := range samples {
		st := sets[h]
		s.URLs, s.IPs, s.Sensors = sortedKeys(st["u"]), sortedKeys(st["i"]), sortedKeys(st["n"])
		s.Sessions = len(st["s"])
		for _, ip := range s.IPs {
			if a := d.attByIP[ip]; a != nil {
				if s.Family == "" && len(a.Families) > 0 {
					s.Family = a.Families[0]
				}
				if a.Campaign != "" {
					s.Campaign = a.Campaign
				}
			}
		}
		out.Samples = append(out.Samples, *s)
	}
	sort.Slice(out.Samples, func(i, j int) bool {
		if len(out.Samples[i].IPs) != len(out.Samples[j].IPs) {
			return len(out.Samples[i].IPs) > len(out.Samples[j].IPs)
		}
		return out.Samples[i].Last.After(out.Samples[j].Last)
	})
	hosts := map[string]*CredStat{}
	for u, x := range urls {
		x.IPs = len(urlIPs[u])
		if x.SHA256 == "" {
			x.SHA256 = urlHash[u]
		}
		out.URLs = append(out.URLs, *x)
		if x.Host != "" {
			h := hosts[x.Host]
			if h == nil {
				h = &CredStat{Value: x.Host}
				hosts[x.Host] = h
			}
			h.Count += x.Count
			h.IPs += x.IPs
		}
	}
	sort.Slice(out.URLs, func(i, j int) bool { return out.URLs[i].Count > out.URLs[j].Count })
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, *h)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Count > out.Hosts[j].Count })
	if out.Samples == nil {
		out.Samples = []Sample{}
	}
	if out.URLs == nil {
		out.URLs = []URLStat{}
	}
	if out.Hosts == nil {
		out.Hosts = []CredStat{}
	}
	return out
}

// ---- MITRE -----------------------------------------------------------------

type TechStat struct {
	intel.Technique
	Sessions  int    `json:"sessions"`
	Attackers int    `json:"attackers"`
	Example   string `json:"example_session,omitempty"`
}

type MitreColumn struct {
	Tactic     string     `json:"tactic"`
	Techniques []TechStat `json:"techniques"`
}

func (d *Dataset) Mitre() []MitreColumn {
	stats := map[string]*TechStat{}
	ips := map[string]map[string]bool{}
	for _, s := range d.Sessions {
		for _, t := range s.Techniques {
			x := stats[t.ID]
			if x == nil {
				x = &TechStat{Technique: t, Example: s.ID}
				stats[t.ID] = x
				ips[t.ID] = map[string]bool{}
			}
			x.Sessions++
			ips[t.ID][s.IP] = true
		}
	}
	cols := make([]MitreColumn, len(intel.TacticOrder))
	idx := map[string]int{}
	for i, t := range intel.TacticOrder {
		cols[i].Tactic = t
		cols[i].Techniques = []TechStat{}
		idx[t] = i
	}
	for id, x := range stats {
		x.Attackers = len(ips[id])
		if i, ok := idx[x.Tactic]; ok {
			cols[i].Techniques = append(cols[i].Techniques, *x)
		}
	}
	for i := range cols {
		ts := cols[i].Techniques
		sort.Slice(ts, func(a, b int) bool { return ts[a].Sessions > ts[b].Sessions })
	}
	return cols
}

// ---- sensors ---------------------------------------------------------------

type SensorInfo struct {
	ID        string         `json:"id"`
	Source    string         `json:"source"`
	Events    int            `json:"events"`
	Attackers int            `json:"attackers"`
	First     time.Time      `json:"first_seen"`
	Last      time.Time      `json:"last_seen"`
	Status    string         `json:"status"` // live | idle | silent | never
	Spark     []int          `json:"spark"`  // last 24h, hourly
	Kinds     map[string]int `json:"kinds"`
	Last24h   int            `json:"events_24h"`
	Countries []CountryStat  `json:"top_countries"`
}

func Sensors(all []*model.Event, known map[string]string, now time.Time) []SensorInfo {
	byS := map[string]*SensorInfo{}
	ips := map[string]map[string]bool{}
	cnt := map[string]map[string]int{}
	cname := map[string]map[string]string{}
	for id, src := range known {
		byS[id] = &SensorInfo{ID: id, Source: src, Spark: make([]int, 24), Kinds: map[string]int{}, Countries: []CountryStat{}}
		ips[id] = map[string]bool{}
		cnt[id] = map[string]int{}
		cname[id] = map[string]string{}
	}
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	for _, e := range all {
		s := byS[e.Sensor]
		if s == nil {
			continue
		}
		s.Events++
		if s.First.IsZero() || e.Time.Before(s.First) {
			s.First = e.Time
		}
		if e.Time.After(s.Last) {
			s.Last = e.Time
		}
		s.Kinds[e.Kind]++
		if e.IP != "" {
			ips[e.Sensor][e.IP] = true
		}
		if e.Geo.CountryCode != "" {
			cnt[e.Sensor][e.Geo.CountryCode]++
			cname[e.Sensor][e.Geo.CountryCode] = e.Geo.CountryName
		}
		if !e.Time.Before(start) {
			if i := int(e.Time.Sub(start) / time.Hour); i >= 0 && i < 24 {
				s.Spark[i]++
			}
			s.Last24h++
		}
	}
	out := make([]SensorInfo, 0, len(byS))
	for id, s := range byS {
		s.Attackers = len(ips[id])
		age := now.Sub(s.Last)
		switch {
		case s.Events == 0:
			s.Status = "never"
		case age <= 30*time.Minute:
			s.Status = "live"
		case age <= 24*time.Hour:
			s.Status = "idle"
		default:
			s.Status = "silent"
		}
		for code, n := range cnt[id] {
			s.Countries = append(s.Countries, CountryStat{Code: code, Name: cname[id][code], Events: n})
		}
		sort.Slice(s.Countries, func(i, j int) bool { return s.Countries[i].Events > s.Countries[j].Events })
		if len(s.Countries) > 5 {
			s.Countries = s.Countries[:5]
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- IOCs ------------------------------------------------------------------

type IOC struct {
	Type    string `json:"type"` // ip | url | sha256 | domain
	Value   string `json:"value"`
	Context string `json:"context"`
	Risk    int    `json:"risk,omitempty"`
}

func (d *Dataset) IOCs(minRisk int) []IOC {
	out := []IOC{}
	for _, a := range d.Attackers {
		if a.Risk >= minRisk {
			ctx := a.Class
			if a.Geo.CountryCode != "" {
				ctx += " / " + a.Geo.CountryCode
			}
			out = append(out, IOC{"ip", a.IP, ctx, a.Risk})
		}
	}
	m := d.Malware()
	for _, s := range m.Samples {
		out = append(out, IOC{"sha256", s.SHA256, "captured payload", 0})
	}
	seenHost := map[string]bool{}
	for _, u := range m.URLs {
		out = append(out, IOC{"url", u.URL, "payload distribution", 0})
		if u.Host != "" && !seenHost[u.Host] && !isIP(u.Host) {
			seenHost[u.Host] = true
			out = append(out, IOC{"domain", u.Host, "payload host", 0})
		}
		if isIP(u.Host) && !seenHost[u.Host] {
			seenHost[u.Host] = true
			out = append(out, IOC{"ip", u.Host, "payload host", 0})
		}
	}
	return out
}

var reIPv4 = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

func isIP(s string) bool { return reIPv4.MatchString(s) }
