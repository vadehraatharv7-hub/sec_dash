// Package model defines the normalized event schema used across SecDash.
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"time"
)

// Event kinds (normalized, sensor-independent).
const (
	KindConnect       = "connect"
	KindClientVersion = "client_version"
	KindLoginFailed   = "login_failed"
	KindLoginSuccess  = "login_success"
	KindCommand       = "command"
	KindCommandFailed = "command_failed"
	KindDownload      = "download"
	KindUpload        = "upload"
	KindForward       = "tcp_forward"
	KindClose         = "close"
	KindHTTP          = "http_request"
	KindOther         = "other"
)

// Geo is the geolocation/ASN enrichment for a source IP.
type Geo struct {
	CountryCode string  `json:"country_code" bson:"country_code"`
	CountryName string  `json:"country_name" bson:"country_name"`
	City        string  `json:"city" bson:"city"`
	Latitude    float64 `json:"latitude" bson:"latitude"`
	Longitude   float64 `json:"longitude" bson:"longitude"`
	ASN         string  `json:"asn,omitempty" bson:"asn,omitempty"`
	Org         string  `json:"org,omitempty" bson:"org,omitempty"`
}

// Event is one normalized honeypot event.
type Event struct {
	Time     time.Time `json:"ts"`
	Sensor   string    `json:"sensor"`
	Source   string    `json:"source"` // cowrie | snare
	Kind     string    `json:"kind"`
	RawType  string    `json:"eventid"`
	Session  string    `json:"session"`
	IP       string    `json:"src_ip"`
	Port     int       `json:"src_port,omitempty"`
	DstPort  int       `json:"dst_port,omitempty"`
	Proto    string    `json:"protocol"`
	User     string    `json:"username,omitempty"`
	Pass     string    `json:"password,omitempty"`
	Input    string    `json:"input,omitempty"`
	Client   string    `json:"client,omitempty"`
	URL      string    `json:"url,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Duration float64   `json:"duration,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	Geo      Geo       `json:"geo"`
}

// Stored is the MongoDB document shape. It stays compatible with documents
// written by earlier SecDash versions so existing data keeps loading.
type Stored struct {
	EventID  string    `bson:"eventid"`
	Sensor   string    `bson:"sensor_id"`
	Source   string    `bson:"honeypot_source"`
	Time     time.Time `bson:"timestamp"`
	Session  string    `bson:"session"`
	IP       string    `bson:"src_ip"`
	Port     int       `bson:"src_port"`
	DstPort  int       `bson:"dst_port"`
	Proto    string    `bson:"protocol"`
	User     string    `bson:"username,omitempty"`
	Pass     string    `bson:"password,omitempty"`
	Input    string    `bson:"input,omitempty"`
	Client   string    `bson:"ssh_version,omitempty"`
	URL      string    `bson:"download_url,omitempty"`
	SHA256   string    `bson:"sha256,omitempty"`
	Size     int64     `bson:"file_size,omitempty"`
	Duration float64   `bson:"duration,omitempty"`
	Geo      Geo       `bson:"geo"`
}

// Fingerprint identifies an event by its content. Two copies of the same event
// (a retried insert, a re-sent batch) share a fingerprint. Time is truncated to
// milliseconds because that is all MongoDB stores.
func (e *Event) Fingerprint() string {
	h := sha1.New()
	for _, f := range []string{
		strconv.FormatInt(e.Time.UnixMilli(), 10), e.Sensor, e.RawType, e.Session, e.IP,
		strconv.Itoa(e.Port), strconv.Itoa(e.DstPort), e.User, e.Pass, e.Input, e.URL, e.SHA256,
		e.Client, e.Method, e.Path, strconv.FormatFloat(e.Duration, 'f', 3, 64),
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}
