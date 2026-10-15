package analytics

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
)

func hash8(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

// Campaign is a group of attacker IPs tied together by shared indicators:
// identical payload hashes, payload URLs, or identical command playbooks.
type Campaign struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	IPs         []string          `json:"ips"`
	Attackers   int               `json:"attackers"`
	Sessions    int               `json:"sessions"`
	Events      int               `json:"events"`
	First       time.Time         `json:"first_seen"`
	Last        time.Time         `json:"last_seen"`
	Countries   []string          `json:"countries"`
	Sensors     []string          `json:"sensors"`
	Hashes      []string          `json:"hashes"`
	URLs        []string          `json:"urls"`
	Playbooks   []Playbook        `json:"playbooks"`
	Families    []string          `json:"families"`
	Techniques  []intel.Technique `json:"techniques"`
	Risk        int               `json:"risk"`
	SharedBasis []string          `json:"linked_by"`
}

// Playbook is a recurring command sequence.
type Playbook struct {
	Hash     string   `json:"hash"`
	Commands []string `json:"commands"`
	Sessions int      `json:"sessions"`
	IPs      int      `json:"ips"`
}

type uf map[string]string

func (u uf) find(x string) string {
	if _, ok := u[x]; !ok {
		u[x] = x
	}
	for u[x] != x {
		u[x] = u[u[x]]
		x = u[x]
	}
	return x
}
func (u uf) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u[ra] = rb
	}
}

func (d *Dataset) buildCampaigns() {
	u := uf{}
	indicator := map[string]string{} // indicator -> first ip
	basis := map[string]map[string]bool{}
	link := func(ip, ind, kind string) {
		u.find(ip)
		if first, ok := indicator[ind]; ok {
			if first != ip {
				u.union(first, ip)
				for _, who := range []string{first, ip} {
					r := who
					if basis[r] == nil {
						basis[r] = map[string]bool{}
					}
					basis[r][kind] = true
				}
			}
		} else {
			indicator[ind] = ip
		}
	}
	for _, s := range d.Sessions {
		if s.IP == "" {
			continue
		}
		for _, e := range s.evs {
			if e.SHA256 != "" {
				link(s.IP, "h:"+e.SHA256, "payload hash")
			}
			if e.URL != "" {
				link(s.IP, "u:"+e.URL, "payload URL")
			}
		}
		if s.Fingerprint != "" && s.Commands >= 3 {
			link(s.IP, "f:"+s.Fingerprint, "command playbook")
		}
	}

	groups := map[string][]string{}
	for ip := range u {
		if d.attByIP[ip] == nil {
			continue
		}
		groups[u.find(ip)] = append(groups[u.find(ip)], ip)
	}
	for _, ips := range groups {
		if len(ips) < 2 {
			continue
		}
		sort.Strings(ips)
		c := &Campaign{IPs: ips, Attackers: len(ips)}
		ipSet := map[string]bool{}
		for _, ip := range ips {
			ipSet[ip] = true
		}
		hashes, urls, countries, sensors, fams := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
		tech := map[string]intel.Technique{}
		pbs := map[string]*Playbook{}
		pbIPs := map[string]map[string]bool{}
		bases := map[string]bool{}
		for _, ip := range ips {
			for k := range basis[ip] {
				bases[k] = true
			}
			a := d.attByIP[ip]
			a.Campaign = ""
			c.Events += a.Events
			if c.First.IsZero() || a.First.Before(c.First) {
				c.First = a.First
			}
			if a.Last.After(c.Last) {
				c.Last = a.Last
			}
			if a.Geo.CountryCode != "" {
				countries[a.Geo.CountryCode] = true
			}
			for _, sn := range a.Sensors {
				sensors[sn] = true
			}
			for _, f := range a.Families {
				fams[f] = true
			}
			for _, t := range a.Techniques {
				tech[t.ID] = t
			}
			if a.Risk > c.Risk {
				c.Risk = a.Risk
			}
		}
		for _, s := range d.Sessions {
			if !ipSet[s.IP] {
				continue
			}
			c.Sessions++
			for _, e := range s.evs {
				if e.SHA256 != "" {
					hashes[e.SHA256] = true
				}
				if e.URL != "" {
					urls[e.URL] = true
				}
			}
			if s.Fingerprint != "" && s.Commands >= 2 {
				pb := pbs[s.Fingerprint]
				if pb == nil {
					pb = &Playbook{Hash: s.Fingerprint}
					for _, e := range s.evs {
						if e.Kind == model.KindCommand && len(pb.Commands) < 12 {
							pb.Commands = append(pb.Commands, e.Input)
						}
					}
					pbs[s.Fingerprint] = pb
					pbIPs[s.Fingerprint] = map[string]bool{}
				}
				pb.Sessions++
				pbIPs[s.Fingerprint][s.IP] = true
			}
		}
		for h, pb := range pbs {
			pb.IPs = len(pbIPs[h])
			c.Playbooks = append(c.Playbooks, *pb)
		}
		sort.Slice(c.Playbooks, func(i, j int) bool { return c.Playbooks[i].Sessions > c.Playbooks[j].Sessions })
		if len(c.Playbooks) > 5 {
			c.Playbooks = c.Playbooks[:5]
		}
		c.Hashes, c.URLs = sortedKeys(hashes), sortedKeys(urls)
		c.Countries, c.Sensors, c.Families = sortedKeys(countries), sortedKeys(sensors), sortedKeys(fams)
		c.SharedBasis = sortedKeys(bases)
		for _, t := range tech {
			c.Techniques = append(c.Techniques, t)
		}
		intel.SortTechniques(c.Techniques)
		c.ID = hash8(strings.Join(ips, ","))[:6]
		switch {
		case len(c.Families) > 0:
			c.Name = c.Families[0]
		case len(c.Hashes) > 0:
			c.Name = "Payload " + c.Hashes[0][:8]
		case len(c.Playbooks) > 0:
			c.Name = "Playbook " + c.Playbooks[0].Hash
		default:
			c.Name = "Coordinated activity"
		}
		for _, ip := range ips {
			d.attByIP[ip].Campaign = c.ID
		}
		d.campaigns = append(d.campaigns, c)
	}
	sort.Slice(d.campaigns, func(i, j int) bool {
		if d.campaigns[i].Attackers != d.campaigns[j].Attackers {
			return d.campaigns[i].Attackers > d.campaigns[j].Attackers
		}
		return d.campaigns[i].Events > d.campaigns[j].Events
	})
}

// Campaigns returns detected campaigns, largest first.
func (d *Dataset) Campaigns() []*Campaign {
	if d.campaigns == nil {
		return []*Campaign{}
	}
	return d.campaigns
}
