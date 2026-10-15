package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sec_dash/backend/internal/analytics"
	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

func qint(r *http.Request, k string, def, max int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil && v >= 0 {
		if max > 0 && v > max {
			return max
		}
		return v
	}
	return def
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]interface{}{
		"status": "healthy", "uptime": time.Since(s.started).Round(time.Second).String(), "events_in_memory": s.st.Len(),
	})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	required := s.authRequired()
	ok := !required || s.tokenOK(r)
	if !ok && r.Header.Get("Authorization") != "" { // a wrong credential counts toward the lockout
		if !s.limiter.allow(r.RemoteAddr) {
			fail(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		s.limiter.fail(r.RemoteAddr)
	}
	mode := "token"
	if s.auth.HasUsers() {
		mode = "password"
	}
	user := ""
	if ok && required {
		user, _ = s.auth.Check(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	respond(w, http.StatusOK, map[string]interface{}{"required": required, "ok": ok, "mode": mode, "user": user})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(r.RemoteAddr) {
		fail(w, http.StatusTooManyRequests, "too many failed attempts, wait a minute")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, ok := s.auth.Verify(req.Username, req.Password)
	if !ok {
		s.limiter.fail(r.RemoteAddr)
		fail(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	tok, exp := s.auth.Issue(u)
	respond(w, http.StatusOK, map[string]interface{}{"token": tok, "expires": exp, "user": u.Name, "role": u.Role})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	type sensor struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	ss := []sensor{}
	for id, src := range s.st.Sensors() {
		ss = append(ss, sensor{id, src})
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].ID < ss[j].ID })
	respond(w, http.StatusOK, map[string]interface{}{
		"sensors": ss, "events_in_memory": s.st.Len(), "auth_required": s.authRequired(),
		"uptime_seconds": int(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	p := params(r)
	ds := s.dataset(p, 0)
	var prev *analytics.Dataset
	if dur := analytics.RangeDuration(p.Range); dur > 0 {
		prev = s.dataset(p, dur)
	}
	sensors := []string{}
	for id := range s.st.Sensors() {
		sensors = append(sensors, id)
	}
	sort.Strings(sensors)
	ov := analytics.BuildOverview(ds, prev, sensors)
	for _, a := range ov.TopAttackers {
		_ = a
	}
	respond(w, http.StatusOK, ov)
}

func (s *Server) handleGeo(w http.ResponseWriter, r *http.Request) {
	ds := s.dataset(params(r), 0)
	respond(w, http.StatusOK, map[string]interface{}{"points": ds.GeoPoints(), "countries": ds.Countries(40)})
}

// ---- events ----------------------------------------------------------------

type eventView struct {
	*model.Event
	Category   string   `json:"category,omitempty"`
	Label      string   `json:"label,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

func viewOf(e *model.Event) eventView {
	v := eventView{Event: e}
	switch e.Kind {
	case model.KindCommand:
		cats, ts := intel.ClassifyCommand(e.Input)
		v.Category = intel.PrimaryCategory(cats)
		for _, t := range ts {
			v.Techniques = append(v.Techniques, t.ID)
		}
	case model.KindHTTP:
		label, t := intel.ClassifyWeb(e.Path)
		v.Label, v.Techniques = label, []string{t.ID}
		if t.ID == "T1190" {
			v.Category = "exploit"
		} else {
			v.Category = "recon"
		}
	case model.KindDownload, model.KindUpload:
		v.Category = "download"
	}
	return v
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	kinds := map[string]bool{}
	for _, k := range strings.Split(r.URL.Query().Get("kind"), ",") {
		if k != "" {
			kinds[k] = true
		}
	}
	ip, sess := r.URL.Query().Get("ip"), r.URL.Query().Get("session")
	p := params(r)
	limit := qint(r, "limit", 100, 500)
	var before time.Time
	if ms, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64); err == nil && ms > 0 {
		before = time.UnixMilli(ms)
	}
	var from time.Time
	if dur := analytics.RangeDuration(p.Range); dur > 0 && r.URL.Query().Get("range") != "" {
		from = time.Now().Add(-dur)
	}
	out := make([]eventView, 0, limit)
	scanned := 0
	s.st.View(func(all []*model.Event) {
		for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
			e := all[i]
			if !from.IsZero() && e.Time.Before(from) {
				break
			}
			if !before.IsZero() && !e.Time.Before(before) {
				continue
			}
			scanned++
			if p.Sensor != "" && e.Sensor != p.Sensor {
				continue
			}
			if len(kinds) > 0 && !kinds[e.Kind] {
				continue
			}
			if ip != "" && e.IP != ip {
				continue
			}
			if sess != "" && e.Session != sess {
				continue
			}
			if q != "" && !matches(e, q) {
				continue
			}
			out = append(out, viewOf(e))
		}
	})
	respond(w, http.StatusOK, map[string]interface{}{"events": out, "scanned": scanned})
}

func matches(e *model.Event, q string) bool {
	for _, f := range []string{e.IP, e.User, e.Pass, e.Input, e.URL, e.SHA256, e.Session, e.Geo.CountryName, e.Geo.City, e.Client, e.Path, e.Sensor} {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

// ---- attackers -------------------------------------------------------------

func (s *Server) handleAttackers(w http.ResponseWriter, r *http.Request) {
	ds := s.dataset(params(r), 0)
	q := strings.ToLower(r.URL.Query().Get("q"))
	class := r.URL.Query().Get("class")
	minRisk := qint(r, "min_risk", 0, 100)
	sortBy := r.URL.Query().Get("sort")
	list := make([]*analytics.Attacker, 0, len(ds.Attackers))
	for _, a := range ds.Attackers {
		if a.Risk < minRisk || (class != "" && a.Class != class) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(a.IP+" "+a.Geo.CountryName+" "+a.Geo.City+" "+a.Geo.Org+" "+a.Geo.ASN), q) {
			continue
		}
		list = append(list, a)
	}
	switch sortBy {
	case "events":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Events > list[j].Events })
	case "recent":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Last.After(list[j].Last) })
	case "sessions":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Sessions > list[j].Sessions })
	}
	total := len(list)
	off, lim := qint(r, "offset", 0, 0), qint(r, "limit", 50, 500)
	if off > total {
		off = total
	}
	end := off + lim
	if end > total {
		end = total
	}
	banned := s.bans.set()
	type row struct {
		*analytics.Attacker
		Banned bool `json:"banned"`
	}
	rows := make([]row, 0, end-off)
	for _, a := range list[off:end] {
		rows = append(rows, row{a, banned[a.IP]})
	}
	respond(w, http.StatusOK, map[string]interface{}{"total": total, "attackers": rows})
}

func (s *Server) handleAttacker(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	p := params(r)
	if r.URL.Query().Get("range") == "" {
		p.Range = "all"
	}
	det := s.dataset(p, 0).AttackerDetail(ip)
	if det == nil {
		fail(w, http.StatusNotFound, "no activity from that IP in the selected range")
		return
	}
	respond(w, http.StatusOK, map[string]interface{}{"detail": det, "banned": s.bans.set()[ip]})
}

// ---- sessions --------------------------------------------------------------

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	ds := s.dataset(params(r), 0)
	q := strings.ToLower(r.URL.Query().Get("q"))
	outcomes := map[string]bool{}
	for _, o := range strings.Split(r.URL.Query().Get("outcome"), ",") {
		if o != "" {
			outcomes[o] = true
		}
	}
	ip := r.URL.Query().Get("ip")
	tech := r.URL.Query().Get("technique")
	list := make([]*analytics.Session, 0, len(ds.Sessions))
	counts := map[string]int{}
	for _, se := range ds.Sessions {
		if ip != "" && se.IP != ip {
			continue
		}
		if tech != "" && !hasTech(se, tech) {
			continue
		}
		if q != "" && !sessionMatches(se, q) {
			continue
		}
		counts[se.Outcome]++
		if len(outcomes) > 0 && !outcomes[se.Outcome] {
			continue
		}
		list = append(list, se)
	}
	switch r.URL.Query().Get("sort") {
	case "severity":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Severity > list[j].Severity })
	case "duration":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Duration > list[j].Duration })
	case "commands":
		sort.SliceStable(list, func(i, j int) bool { return list[i].Commands > list[j].Commands })
	}
	total := len(list)
	off, lim := qint(r, "offset", 0, 0), qint(r, "limit", 50, 500)
	if off > total {
		off = total
	}
	end := off + lim
	if end > total {
		end = total
	}
	respond(w, http.StatusOK, map[string]interface{}{"total": total, "outcomes": counts, "sessions": list[off:end]})
}

func sessionMatches(s *analytics.Session, q string) bool {
	if strings.Contains(strings.ToLower(s.ID+" "+s.IP+" "+s.Geo.CountryName+" "+s.Username+" "+s.Client+" "+s.Sensor), q) {
		return true
	}
	return analytics.SessionHasText(s, q)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p := params(r)
	p.Range = "all"
	det := s.dataset(p, 0).SessionDetail(id)
	if det == nil {
		fail(w, http.StatusNotFound, "session not found")
		return
	}
	respond(w, http.StatusOK, det)
}

// ---- intel views -----------------------------------------------------------

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.dataset(params(r), 0).Credentials(qint(r, "limit", 25, 200)))
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.dataset(params(r), 0).Commands(qint(r, "limit", 40, 300)))
}

func (s *Server) handleMalware(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.dataset(params(r), 0).Malware())
}

func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.dataset(params(r), 0).Campaigns())
}

func (s *Server) handleMitre(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.dataset(params(r), 0).Mitre())
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	var all []*model.Event
	s.st.View(func(a []*model.Event) { all = append(all, a...) })
	respond(w, http.StatusOK, analytics.Sensors(all, s.st.Sensors(), time.Now().UTC()))
}

func (s *Server) handleIOCs(w http.ResponseWriter, r *http.Request) {
	iocs := s.dataset(params(r), 0).IOCs(qint(r, "min_risk", 35, 100))
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="secdash-iocs.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"type", "value", "context", "risk"})
		for _, i := range iocs {
			_ = cw.Write([]string{i.Type, i.Value, i.Context, strconv.Itoa(i.Risk)})
		}
		cw.Flush()
	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", `attachment; filename="secdash-blocklist.txt"`)
		for _, i := range iocs {
			if i.Type == "ip" {
				fmt.Fprintln(w, i.Value)
			}
		}
	default:
		respond(w, http.StatusOK, iocs)
	}
}

func hasTech(s *analytics.Session, id string) bool {
	for _, t := range s.Techniques {
		if t.ID == id {
			return true
		}
	}
	return false
}
