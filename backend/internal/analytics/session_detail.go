package analytics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

// TimelineItem is one line of a session replay.
type TimelineItem struct {
	Offset     float64           `json:"offset"`
	Time       time.Time         `json:"ts"`
	Kind       string            `json:"kind"`
	Text       string            `json:"text"`
	Detail     string            `json:"detail,omitempty"`
	Category   string            `json:"category,omitempty"`
	Techniques []intel.Technique `json:"techniques,omitempty"`
	OK         *bool             `json:"ok,omitempty"`
}

type Phase struct {
	Number   int    `json:"number"`
	Name     string `json:"name"`
	Achieved bool   `json:"achieved"`
	Evidence string `json:"evidence,omitempty"`
	Summary  string `json:"summary"`
}

type Analysis struct {
	Intent     string   `json:"intent"`
	Skill      string   `json:"skill_level"`
	Category   string   `json:"category"`
	Summary    string   `json:"summary"`
	Confidence int      `json:"confidence"`
	Actions    []string `json:"recommended_actions"`
	Model      string   `json:"model"`
}

type SessionDetail struct {
	Session    *Session       `json:"session"`
	Timeline   []TimelineItem `json:"timeline"`
	KillChain  []Phase        `json:"kill_chain"`
	Analysis   *Analysis      `json:"analysis"`
	Attacker   *Attacker      `json:"attacker,omitempty"`
	Commands   []string       `json:"commands"`
	Transcript string         `json:"transcript"`
}

func boolp(b bool) *bool { return &b }

func (d *Dataset) SessionDetail(id string) *SessionDetail {
	s := d.sessByID[id]
	if s == nil {
		return nil
	}
	det := &SessionDetail{Session: s, Attacker: d.attByIP[s.IP], Timeline: []TimelineItem{}}
	var cmds []string
	var tr strings.Builder
	catsSeen := map[string]bool{}
	for _, e := range s.evs {
		it := TimelineItem{Offset: e.Time.Sub(s.Start).Seconds(), Time: e.Time, Kind: e.Kind}
		switch e.Kind {
		case model.KindConnect:
			it.Text = fmt.Sprintf("Connection from %s:%d to port %d (%s)", e.IP, e.Port, e.DstPort, strings.ToUpper(e.Proto))
		case model.KindClientVersion:
			it.Text = "Client banner: " + e.Client
		case model.KindLoginFailed:
			it.Text = fmt.Sprintf("Login failed: %s / %s", e.User, orEmpty(e.Pass))
			it.OK = boolp(false)
		case model.KindLoginSuccess:
			it.Text = fmt.Sprintf("Login succeeded: %s / %s", e.User, orEmpty(e.Pass))
			it.OK = boolp(true)
			it.Techniques = []intel.Technique{intel.T1078}
		case model.KindCommand, model.KindCommandFailed:
			it.Text = e.Input
			cats, ts := intel.ClassifyCommand(e.Input)
			it.Category, it.Techniques = intel.PrimaryCategory(cats), ts
			if e.Kind == model.KindCommand {
				cmds = append(cmds, e.Input)
				fmt.Fprintf(&tr, "$ %s\n", e.Input)
			}
			catsSeen[it.Category] = true
		case model.KindDownload, model.KindUpload:
			it.Text = "File captured: " + e.URL
			it.Detail = fmt.Sprintf("sha256 %s (%d bytes)", e.SHA256, e.Size)
			it.Category = "download"
			it.Techniques = []intel.Technique{intel.T1105}
		case model.KindHTTP:
			label, t := intel.ClassifyWeb(e.Path)
			it.Text = strings.TrimSpace(e.Method + " " + e.Path)
			it.Detail = label
			it.Techniques = []intel.Technique{t}
		case model.KindClose:
			it.Text = fmt.Sprintf("Session closed after %.1fs", e.Duration)
		case model.KindForward:
			it.Text = "TCP/IP forward attempt " + e.Input
			it.Techniques = []intel.Technique{intel.T1090}
		default:
			it.Text = e.RawType
		}
		det.Timeline = append(det.Timeline, it)
	}
	if cmds == nil {
		cmds = []string{}
	}
	det.Commands = cmds
	det.Transcript = tr.String()
	det.KillChain = killChain(s)
	det.Analysis = heuristic(s, d.attByIP[s.IP], cmds)
	return det
}

func orEmpty(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

func killChain(s *Session) []Phase {
	p := []Phase{
		{1, "Reconnaissance", false, "", "Port scanning, banner grabbing and service probing"},
		{2, "Delivery", false, "", "Credential guessing or exploit requests against the service"},
		{3, "Initial Access", false, "", "Valid credentials accepted - interactive access granted"},
		{4, "Discovery", false, "", "Enumerating the host: OS, hardware, users, network"},
		{5, "Tool Transfer", false, "", "Staging second-stage payloads onto the host"},
		{6, "Execution & Persistence", false, "", "Running payloads, cron / SSH-key persistence"},
		{7, "Defense Evasion & Impact", false, "", "Clearing traces, disabling firewall, mining or destruction"},
	}
	set := func(i int, ev string) {
		if !p[i].Achieved {
			p[i].Achieved, p[i].Evidence = true, ev
		}
	}
	for _, e := range s.evs {
		switch e.Kind {
		case model.KindConnect, model.KindClientVersion:
			set(0, fmt.Sprintf("connection to :%d", e.DstPort))
		case model.KindLoginFailed:
			set(0, "connection to service")
			set(1, fmt.Sprintf("tried %s / %s", e.User, orEmpty(e.Pass)))
		case model.KindLoginSuccess:
			set(0, "connection to service")
			set(1, fmt.Sprintf("tried %s / %s", e.User, orEmpty(e.Pass)))
			set(2, fmt.Sprintf("authenticated as %s", e.User))
		case model.KindHTTP:
			set(0, e.Path)
			if _, t := intel.ClassifyWeb(e.Path); t.ID == "T1190" {
				set(1, e.Method+" "+e.Path)
			}
		case model.KindDownload, model.KindUpload:
			set(4, e.URL)
		case model.KindCommand:
			cats, _ := intel.ClassifyCommand(e.Input)
			for _, c := range cats {
				switch c {
				case "recon":
					set(3, e.Input)
				case "download":
					set(4, e.Input)
				case "execution", "reverse_shell":
					set(5, e.Input)
				case "persistence":
					set(5, e.Input)
				case "evasion", "miner", "destructive":
					set(6, e.Input)
				}
			}
		}
	}
	return p
}

func heuristic(s *Session, a *Attacker, cmds []string) *Analysis {
	ip := s.IP
	if ip == "" {
		ip = "an unidentified source"
	}
	an := &Analysis{Model: "SecDash rule engine", Confidence: 80}
	techNames := make([]string, 0, len(s.Techniques))
	for _, t := range s.Techniques {
		techNames = append(techNames, t.ID+" "+t.Name)
	}
	fam := ""
	if len(s.Families) > 0 {
		fam = s.Families[0]
	}
	block := fmt.Sprintf("Block %s at the network edge", ip)
	switch s.Outcome {
	case "malware":
		an.Category, an.Skill, an.Confidence = "Malware delivery", "Automated botnet / script", 92
		an.Intent = "Stage and run a second-stage payload on a compromised host"
		an.Summary = fmt.Sprintf("%s logged in as %q and fetched a payload using %d command(s).", ip, s.Username, s.Commands)
		if fam != "" {
			an.Summary += " Behaviour matches: " + fam + "."
		}
		an.Actions = []string{block, "Submit the captured hash for sandbox analysis", "Hunt for the distribution URL in egress logs"}
	case "intrusion":
		an.Category, an.Skill, an.Confidence = "Interactive intrusion", "Script or manual operator", 85
		an.Intent = "Enumerate the host and look for monetizable access"
		an.Summary = fmt.Sprintf("%s authenticated as %q and ran %d command(s) over %.0fs.", ip, s.Username, s.Commands, s.Duration)
		if fam != "" {
			an.Summary += " Behaviour matches: " + fam + "."
		}
		an.Actions = []string{block, "Review the command list for persistence attempts", "Disable password logins on production SSH"}
	case "login_only":
		an.Category, an.Skill = "Credential validation", "Automated scanner"
		an.Intent = "Verify which credentials work, then hand off to another stage"
		an.Summary = fmt.Sprintf("%s authenticated as %q but ran no commands - typical credential-verification bot.", ip, s.Username)
		an.Actions = []string{block, "Watch for the same IP returning with a different tool"}
	case "brute_force":
		an.Category, an.Skill = "Credential attack", "Automated bruteforcer"
		an.Intent = "Guess valid SSH/Telnet credentials"
		an.Summary = fmt.Sprintf("%s made %d failed login attempts without success.", ip, s.Failed)
		an.Actions = []string{"Enforce key-only SSH", "Rate-limit or fail2ban repeated failures", block}
	case "web":
		an.Category, an.Skill = "Web reconnaissance", "Automated scanner"
		an.Intent = "Find exposed admin panels, secrets or vulnerable software"
		an.Summary = fmt.Sprintf("%d HTTP request(s) probing the web honeypot.", s.Requests)
		if s.Severity >= 40 {
			an.Category, an.Intent = "Web exploitation", "Exploit a known vulnerability in public-facing software"
			an.Confidence = 88
		}
		an.Actions = []string{"Patch and restrict internet-exposed admin interfaces", block}
	default:
		an.Category, an.Skill = "Port scan", "Mass scanner"
		an.Intent = "Discover reachable services"
		an.Summary = fmt.Sprintf("%s connected and disconnected without authenticating.", ip)
		an.Actions = []string{"No action needed; background internet noise"}
	}
	if len(techNames) > 0 {
		an.Summary += " ATT&CK: " + strings.Join(techNames, ", ") + "."
	}
	if a != nil && a.Sessions > 1 {
		an.Summary += fmt.Sprintf(" This IP appears in %d sessions.", a.Sessions)
	}
	_ = cmds
	return an
}

// ---- attacker detail -------------------------------------------------------

type AttackerDetail struct {
	Attacker    *Attacker  `json:"attacker"`
	Sessions    []*Session `json:"sessions"`
	Credentials []PairStat `json:"credentials"`
	Commands    []CmdStat  `json:"commands"`
	Timeline    []Bucket   `json:"timeline"`
	Campaign    *Campaign  `json:"campaign,omitempty"`
	Paths       []CredStat `json:"paths,omitempty"`
}

func (d *Dataset) AttackerDetail(ip string) *AttackerDetail {
	a := d.attByIP[ip]
	if a == nil {
		return nil
	}
	det := &AttackerDetail{Attacker: a, Sessions: []*Session{}, Credentials: []PairStat{}, Commands: []CmdStat{}, Paths: []CredStat{}}
	for _, s := range d.Sessions {
		if s.IP == ip {
			det.Sessions = append(det.Sessions, s)
		}
	}
	sub := &Dataset{P: d.P, From: a.First, To: a.Last.Add(time.Second), sessByID: d.sessByID, attByIP: d.attByIP}
	pairs := map[string]*PairStat{}
	cmds := map[string]*CmdStat{}
	paths := map[string]int{}
	for _, e := range d.Events {
		if e.IP != ip {
			continue
		}
		sub.Events = append(sub.Events, e)
		switch e.Kind {
		case model.KindLoginFailed, model.KindLoginSuccess:
			k := e.User + "\x00" + e.Pass
			p := pairs[k]
			if p == nil {
				p = &PairStat{User: e.User, Pass: e.Pass}
				pairs[k] = p
			}
			p.Count++
			p.IPs = 1
			if e.Kind == model.KindLoginSuccess {
				p.Success++
			}
			p.Last = e.Time
		case model.KindCommand:
			k := intel.NormalizeCommand(e.Input)
			c := cmds[k]
			if c == nil {
				cats, ts := intel.ClassifyCommand(e.Input)
				c = &CmdStat{Command: k, Sample: e.Input, Category: intel.PrimaryCategory(cats), Categories: cats, Techniques: ts, First: e.Time}
				cmds[k] = c
			}
			c.Count++
			c.Last = e.Time
		case model.KindHTTP:
			paths[strings.TrimSpace(e.Method+" "+e.Path)]++
		}
	}
	det.Timeline, _ = sub.Timeline()
	for _, p := range pairs {
		det.Credentials = append(det.Credentials, *p)
	}
	sort.Slice(det.Credentials, func(i, j int) bool { return det.Credentials[i].Count > det.Credentials[j].Count })
	if len(det.Credentials) > 30 {
		det.Credentials = det.Credentials[:30]
	}
	for _, c := range cmds {
		det.Commands = append(det.Commands, *c)
	}
	sort.Slice(det.Commands, func(i, j int) bool { return det.Commands[i].Count > det.Commands[j].Count })
	if len(det.Commands) > 30 {
		det.Commands = det.Commands[:30]
	}
	for p, n := range paths {
		det.Paths = append(det.Paths, CredStat{Value: p, Count: n})
	}
	sort.Slice(det.Paths, func(i, j int) bool { return det.Paths[i].Count > det.Paths[j].Count })
	if len(det.Paths) > 30 {
		det.Paths = det.Paths[:30]
	}
	if len(det.Sessions) > 50 {
		det.Sessions = det.Sessions[:50]
	}
	for _, c := range d.campaigns {
		if c.ID == a.Campaign {
			det.Campaign = c
		}
	}
	return det
}

// SessionHasText reports whether any command/URL/credential in the session contains q (lower-case).
func SessionHasText(s *Session, q string) bool {
	for _, e := range s.evs {
		for _, f := range []string{e.Input, e.URL, e.User, e.Pass, e.Path, e.SHA256} {
			if f != "" && strings.Contains(strings.ToLower(f), q) {
				return true
			}
		}
	}
	return false
}
