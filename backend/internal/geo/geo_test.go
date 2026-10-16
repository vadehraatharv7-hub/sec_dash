package geo

import (
	"testing"
	"time"

	"sec_dash/backend/internal/model"
)

func newTestResolver() *Resolver {
	return &Resolver{
		cache: map[string]model.Geo{}, failed: map[string]time.Time{}, pending: map[string]bool{},
		queue: make(chan string, 8), online: true,
	}
}

func TestFailedLookupsAreRetriedLater(t *testing.T) {
	r := newTestResolver()
	ip := "81.24.135.206"
	r.failed[ip] = time.Now().Add(time.Hour)
	if g := r.Lookup(ip); g.CountryCode != "" || len(r.queue) != 0 {
		t.Fatal("within the back-off window nothing should be queued")
	}
	r.failed[ip] = time.Now().Add(-time.Minute) // back-off over
	r.Lookup(ip)
	if len(r.queue) != 1 {
		t.Fatal("after the back-off the address must be queued again")
	}
}

func TestPrivateAddressesAreNeverLookedUp(t *testing.T) {
	r := newTestResolver()
	r.Lookup("172.18.0.1")
	r.Lookup("10.0.2.4")
	if len(r.queue) != 0 {
		t.Fatal("private addresses must not be sent to an online service")
	}
}
