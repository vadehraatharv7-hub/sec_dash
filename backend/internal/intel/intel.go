// Package intel holds the detection knowledge: command classification, MITRE
// ATT&CK mapping, web-probe signatures and known malware-family markers.
package intel

import (
	"regexp"
	"sort"
	"strings"
)

// Technique is a MITRE ATT&CK technique reference.
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// Tactic order follows the ATT&CK matrix so the UI can lay out a heatmap.
var TacticOrder = []string{
	"Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
	"Defense Evasion", "Credential Access", "Discovery", "Command and Control", "Impact",
}

var (
	T1595   = Technique{"T1595", "Active Scanning", "Reconnaissance"}
	T1595_3 = Technique{"T1595.003", "Wordlist Scanning", "Reconnaissance"}
	T1190   = Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}
	T1078   = Technique{"T1078", "Valid Accounts", "Initial Access"}
	T1110_1 = Technique{"T1110.001", "Password Guessing", "Credential Access"}
	T1110_4 = Technique{"T1110.004", "Credential Stuffing", "Credential Access"}
	T1059_4 = Technique{"T1059.004", "Unix Shell", "Execution"}
	T1053_3 = Technique{"T1053.003", "Cron", "Persistence"}
	T1098_4 = Technique{"T1098.004", "SSH Authorized Keys", "Persistence"}
	T1098   = Technique{"T1098", "Account Manipulation", "Persistence"}
	T1222_2 = Technique{"T1222.002", "Linux File Permissions Modification", "Defense Evasion"}
	T1070_3 = Technique{"T1070.003", "Clear Command History", "Defense Evasion"}
	T1070_4 = Technique{"T1070.004", "File Deletion", "Defense Evasion"}
	T1562_4 = Technique{"T1562.004", "Disable or Modify System Firewall", "Defense Evasion"}
	T1027   = Technique{"T1027", "Obfuscated Files or Information", "Defense Evasion"}
	T1003_8 = Technique{"T1003.008", "/etc/passwd and /etc/shadow", "Credential Access"}
	T1082   = Technique{"T1082", "System Information Discovery", "Discovery"}
	T1033   = Technique{"T1033", "System Owner/User Discovery", "Discovery"}
	T1057   = Technique{"T1057", "Process Discovery", "Discovery"}
	T1016   = Technique{"T1016", "System Network Configuration Discovery", "Discovery"}
	T1083   = Technique{"T1083", "File and Directory Discovery", "Discovery"}
	T1105   = Technique{"T1105", "Ingress Tool Transfer", "Command and Control"}
	T1090   = Technique{"T1090", "Proxy", "Command and Control"}
	T1496   = Technique{"T1496", "Resource Hijacking", "Impact"}
	T1485   = Technique{"T1485", "Data Destruction", "Impact"}
)

type cmdRule struct {
	re       *regexp.Regexp
	category string
	tech     []Technique
}

func rule(pat, cat string, t ...Technique) cmdRule {
	return cmdRule{regexp.MustCompile(`(?i)` + pat), cat, t}
}

var cmdRules = []cmdRule{
	rule(`\b(wget|curl|tftp|ftpget|scp|sftp)\b`, "download", T1105),
	rule(`\bchmod\b[^|;&]*(\+x|[0-7]*[1357][0-7]{0,2}\b|777|755)`, "execution", T1222_2),
	rule(`(\|\s*(ba)?sh\b|\bsh\s+-c\b|bash\s+-c\b|\./[\w.\-/]+|\bnohup\b|/dev/tcp/|\bbusybox\b)`, "execution", T1059_4),
	rule(`(base64\s+(-d|--decode)|\\x[0-9a-f]{2}|printf\s+['"]\\)`, "execution", T1027),
	rule(`\b(crontab|/etc/cron|/etc/rc\.local|systemctl\s+enable|/etc/init\.d|@reboot)\b`, "persistence", T1053_3),
	rule(`(authorized_keys|\.ssh/)`, "persistence", T1098_4),
	rule(`\b(passwd|chpasswd|usermod|useradd|adduser)\b`, "persistence", T1098),
	rule(`(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|>\s*~?/?\.bash_history|rm\s+.*\.bash_history)`, "evasion", T1070_3),
	rule(`(rm\s+-r?f\s|shred\s|rm\s+-rf)`, "evasion", T1070_4),
	rule(`\b(iptables|ufw|firewall-cmd|setenforce)\b`, "evasion", T1562_4),
	rule(`(/etc/shadow|/etc/passwd)`, "credential", T1003_8),
	rule(`\buname\b|/proc/(cpuinfo|version|meminfo)|\blscpu\b|\bfree\b|/etc/(os-release|issue)|\bhostname\b|\bnproc\b|lsb_release|\bdmidecode\b`, "recon", T1082),
	rule(`\b(whoami|id|w|who|last|users|groups)\b`, "recon", T1033),
	rule(`\b(ps|top|pgrep|htop)\b`, "recon", T1057),
	rule(`\b(ifconfig|ip\s+(a|addr|route)|netstat|ss\s+-|route|arp|hostname\s+-I|cat\s+/etc/resolv)\b`, "recon", T1016),
	rule(`\b(ls|find|locate|pwd|df|mount|dir)\b`, "recon", T1083),
	rule(`(xmrig|minerd|cpuminer|stratum\+tcp|ethminer|nicehash|kdevtmpfsi|kinsing|monero|pool\.)`, "miner", T1496),
	rule(`\b(nc|ncat|netcat|socat)\b|bash\s+-i|/dev/tcp`, "reverse_shell", T1059_4, T1090),
	rule(`(rm\s+-rf\s+/\s|mkfs|dd\s+if=/dev/(zero|random)|:\(\)\{)`, "destructive", T1485),
}

// ClassifyCommand returns the categories and ATT&CK techniques of a shell command.
func ClassifyCommand(cmd string) (cats []string, techs []Technique) {
	seenC := map[string]bool{}
	seenT := map[string]bool{}
	for _, r := range cmdRules {
		if !r.re.MatchString(cmd) {
			continue
		}
		if !seenC[r.category] {
			seenC[r.category] = true
			cats = append(cats, r.category)
		}
		for _, t := range r.tech {
			if !seenT[t.ID] {
				seenT[t.ID] = true
				techs = append(techs, t)
			}
		}
	}
	if len(cats) == 0 {
		cats = []string{"other"}
	}
	return
}

// PrimaryCategory picks the most severe category for display.
func PrimaryCategory(cats []string) string {
	rank := map[string]int{"destructive": 9, "miner": 8, "reverse_shell": 8, "persistence": 7, "download": 6,
		"execution": 5, "evasion": 5, "credential": 4, "recon": 2, "other": 0}
	best, bestR := "other", -1
	for _, c := range cats {
		if rank[c] > bestR {
			best, bestR = c, rank[c]
		}
	}
	return best
}

// ---- web probes (Snare) ----------------------------------------------------

type webRule struct {
	re    *regexp.Regexp
	label string
	tech  Technique
}

func wrule(pat, label string, t Technique) webRule {
	return webRule{regexp.MustCompile(`(?i)` + pat), label, t}
}

var webRules = []webRule{
	wrule(`\$\{jndi:|%24%7bjndi`, "Log4Shell (CVE-2021-44228)", T1190),
	wrule(`(vendor/phpunit|eval-stdin\.php)`, "PHPUnit RCE (CVE-2017-9841)", T1190),
	wrule(`(/cgi-bin/|\.cgi\b|/bin/sh|;\s*(wget|curl)|\|\s*sh)`, "CGI / shell injection", T1190),
	wrule(`(\.\./|%2e%2e|/etc/passwd|/proc/self)`, "Path traversal / LFI", T1190),
	wrule(`(boaform|/HNAP1|/setup\.cgi|/GponForm|/ctrlt/DeviceUpgrade|/cgi-bin/luci|/goform/)`, "IoT router exploit probe", T1190),
	wrule(`(actuator|jolokia|/console|/manager/html|/solr/|/jenkins|/api/v1/pods)`, "Admin-console / framework probe", T1190),
	wrule(`(\.env|\.git/|\.svn/|\.aws/|\.ssh/|id_rsa|config\.(php|json|yml)|wp-config|\.DS_Store|backup\.(sql|zip|tar)|\.bak\b)`, "Secrets / config disclosure hunt", T1595_3),
	wrule(`(wp-login|wp-admin|xmlrpc\.php|wp-content|wp-includes)`, "WordPress probe", T1595_3),
	wrule(`(phpmyadmin|pma/|myadmin|adminer|/mysql)`, "Database admin panel probe", T1595_3),
	wrule(`(/admin|/login|/administrator|/signin|/user/login|/dashboard)`, "Login portal probe", T1595_3),
	wrule(`(robots\.txt|sitemap\.xml|favicon\.ico|/$)`, "Basic fingerprinting", T1595),
}

// ClassifyWeb labels an HTTP request path.
func ClassifyWeb(path string) (label string, tech Technique) {
	for _, r := range webRules {
		if r.re.MatchString(path) {
			return r.label, r.tech
		}
	}
	return "Generic web scan", T1595
}

// ---- malware families / campaign tags -------------------------------------

type famRule struct {
	re   *regexp.Regexp
	name string
}

var famRules = []famRule{
	{regexp.MustCompile(`(?i)mdrfckr`), "SSH-key implant (mdrfckr)"},
	{regexp.MustCompile(`(?i)(xmrig|minerd|cpuminer|stratum\+tcp|kdevtmpfsi|kinsing)`), "Cryptominer dropper"},
	{regexp.MustCompile(`(?i)(mirai|ecchi|/bin/busybox\s+\w+|\.(mips|mpsl|arm[0-9a-z]*|x86|sh4|ppc|m68k|spc)\b)`), "Mirai-family IoT botnet"},
	{regexp.MustCompile(`(?i)(gafgyt|bashlite|tsunami|kaiten|lizkebab)`), "Gafgyt / Tsunami botnet"},
	{regexp.MustCompile(`(?i)(\.ICE-unix|dota3?|\.rsyslogds|outlaw)`), "Dota / Outlaw SSH botnet"},
	{regexp.MustCompile(`(?i)(zmap|masscan|nmap)`), "Scanner tooling"},
}

// FamilyOf returns a malware/campaign family label for a string, or "".
func FamilyOf(s string) string {
	for _, f := range famRules {
		if f.re.MatchString(s) {
			return f.name
		}
	}
	return ""
}

// ---- helpers ---------------------------------------------------------------

// SortTechniques orders techniques by tactic then ID.
func SortTechniques(ts []Technique) {
	order := map[string]int{}
	for i, t := range TacticOrder {
		order[t] = i
	}
	sort.Slice(ts, func(i, j int) bool {
		if order[ts[i].Tactic] != order[ts[j].Tactic] {
			return order[ts[i].Tactic] < order[ts[j].Tactic]
		}
		return ts[i].ID < ts[j].ID
	})
}

// NormalizeCommand collapses volatile parts so similar commands group together.
var (
	reIP   = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b(:\d+)?`)
	reHex  = regexp.MustCompile(`\b[0-9a-f]{16,}\b`)
	reNum  = regexp.MustCompile(`\b\d{4,}\b`)
	reSpce = regexp.MustCompile(`\s+`)
)

func NormalizeCommand(c string) string {
	c = strings.TrimSpace(c)
	c = reIP.ReplaceAllString(c, "<ip>")
	c = reHex.ReplaceAllString(c, "<hex>")
	c = reNum.ReplaceAllString(c, "<n>")
	return reSpce.ReplaceAllString(c, " ")
}
