// Package geo resolves source IPs to location and network owner.
//
// Resolution order: local MaxMind-format databases (GeoLite2 / DB-IP) when
// present, then an optional online fallback (ip-api.com batch endpoint) that
// fills in asynchronously. No location is ever invented: unresolved IPs have an
// empty Geo.
package geo

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"

	"sec_dash/backend/internal/model"
)

type Resolver struct {
	city   *geoip2.Reader
	asn    *geoip2.Reader
	online bool

	mu      sync.RWMutex
	cache   map[string]model.Geo
	pending map[string]bool
	queue   chan string

	// OnResolved is called (from a background goroutine) when the online
	// fallback resolves an IP.
	OnResolved func(ip string, g model.Geo)
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// New builds a resolver. GEOIP_CITY_DB / GEOIP_ASN_DB point at .mmdb files;
// GEO_ONLINE=0 disables the online fallback.
func New() *Resolver {
	r := &Resolver{
		cache:   map[string]model.Geo{},
		pending: map[string]bool{},
		queue:   make(chan string, 4096),
		online:  os.Getenv("GEO_ONLINE") != "0",
	}
	cityPath := firstExisting(os.Getenv("GEOIP_CITY_DB"), "GeoLite2-City.mmdb", "dbip-city-lite.mmdb",
		"/home/azureuser/app/backend/GeoLite2-City.mmdb", "/tmp/GeoLite2-City.mmdb")
	if cityPath != "" {
		if db, err := geoip2.Open(cityPath); err == nil {
			r.city = db
			log.Printf("[geo] city database: %s", cityPath)
		}
	}
	asnPath := firstExisting(os.Getenv("GEOIP_ASN_DB"), "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb",
		"/home/azureuser/app/backend/GeoLite2-ASN.mmdb")
	if asnPath != "" {
		if db, err := geoip2.Open(asnPath); err == nil {
			r.asn = db
			log.Printf("[geo] asn database: %s", asnPath)
		}
	}
	if r.city == nil && r.online {
		log.Printf("[geo] no local database; using online lookups (set GEO_ONLINE=0 to disable)")
	}
	if r.online {
		go r.worker()
	}
	return r
}

func isPublic(ip net.IP) bool {
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast()
}

// Lookup returns the best known Geo for an IP (possibly empty) and schedules an
// online lookup if nothing is known yet.
func (r *Resolver) Lookup(ipStr string) model.Geo {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if !isPublic(ip) {
		return model.Geo{}
	}
	r.mu.RLock()
	g, ok := r.cache[ipStr]
	r.mu.RUnlock()
	if ok {
		return g
	}

	if r.city != nil {
		var g model.Geo
		if rec, err := r.city.City(ip); err == nil {
			g.CountryCode = rec.Country.IsoCode
			g.CountryName = rec.Country.Names["en"]
			g.City = rec.City.Names["en"]
			g.Latitude = rec.Location.Latitude
			g.Longitude = rec.Location.Longitude
		}
		if r.asn != nil {
			if rec, err := r.asn.ASN(ip); err == nil && rec.AutonomousSystemNumber != 0 {
				g.ASN = "AS" + itoa(rec.AutonomousSystemNumber)
				g.Org = rec.AutonomousSystemOrganization
			}
		}
		if g.CountryCode != "" {
			r.store(ipStr, g)
			return g
		}
	}
	r.Enqueue(ipStr)
	return model.Geo{}
}

func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (r *Resolver) store(ip string, g model.Geo) {
	r.mu.Lock()
	r.cache[ip] = g
	delete(r.pending, ip)
	r.mu.Unlock()
}

// Enqueue schedules an online lookup for ip.
func (r *Resolver) Enqueue(ip string) {
	if !r.online || !isPublic(net.ParseIP(ip)) {
		return
	}
	r.mu.Lock()
	if r.pending[ip] {
		r.mu.Unlock()
		return
	}
	r.pending[ip] = true
	r.mu.Unlock()
	select {
	case r.queue <- ip:
	default:
		r.mu.Lock()
		delete(r.pending, ip)
		r.mu.Unlock()
	}
}

type apiResult struct {
	Status      string  `json:"status"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	AS          string  `json:"as"`
	Org         string  `json:"org"`
}

// worker batches queued IPs to ip-api.com (limit: 15 batch requests/minute).
func (r *Resolver) worker() {
	client := &http.Client{Timeout: 15 * time.Second}
	tick := time.NewTicker(6 * time.Second)
	defer tick.Stop()
	for range tick.C {
		var batch []string
	drain:
		for len(batch) < 100 {
			select {
			case ip := <-r.queue:
				batch = append(batch, ip)
			default:
				break drain
			}
		}
		if len(batch) == 0 {
			continue
		}
		body, _ := json.Marshal(batch)
		resp, err := client.Post("http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,as,org",
			"application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("[geo] online lookup failed: %v", err)
			r.requeue(batch)
			continue
		}
		var results []apiResult
		err = json.NewDecoder(resp.Body).Decode(&results)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			log.Printf("[geo] online lookup bad response (%d): %v", resp.StatusCode, err)
			r.requeue(batch)
			continue
		}
		for _, a := range results {
			if a.Status != "success" {
				r.store(a.Query, model.Geo{})
				continue
			}
			asn, _, _ := strings.Cut(a.AS, " ")
			g := model.Geo{CountryCode: a.CountryCode, CountryName: a.Country, City: a.City,
				Latitude: a.Lat, Longitude: a.Lon, ASN: asn, Org: a.Org}
			r.store(a.Query, g)
			if r.OnResolved != nil {
				r.OnResolved(a.Query, g)
			}
		}
	}
}

func (r *Resolver) requeue(batch []string) {
	time.Sleep(30 * time.Second)
	for _, ip := range batch {
		select {
		case r.queue <- ip:
		default:
		}
	}
}
