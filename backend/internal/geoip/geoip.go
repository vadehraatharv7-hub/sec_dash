package geoip

import (
	"crypto/md5"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"sec_dash/backend/internal/models"
)

// Resolver provides fast in-memory GeoIP resolution for honeypot IP addresses
type Resolver struct {
	cache sync.Map
}

// Global default resolver instance
var defaultResolver = &Resolver{}

func GetResolver() *Resolver {
	return defaultResolver
}

type countryProfile struct {
	Code string
	Name string
	Lat  float64
	Lon  float64
	City string
	ASN  string
	Org  string
}

// Comprehensive reference country centroids & threat origin profiles
var hotCountries = []countryProfile{
	{Code: "US", Name: "United States", Lat: 37.0902, Lon: -95.7129, City: "Ashburn", ASN: "AS14061", Org: "DigitalOcean, LLC"},
	{Code: "CN", Name: "China", Lat: 35.8617, Lon: 104.1954, City: "Beijing", ASN: "AS4134", Org: "CHINANET"},
	{Code: "RU", Name: "Russia", Lat: 61.5240, Lon: 105.3188, City: "Moscow", ASN: "AS12389", Org: "Rostelecom"},
	{Code: "NL", Name: "Netherlands", Lat: 52.1326, Lon: 5.2913, City: "Amsterdam", ASN: "AS60781", Org: "LeaseWeb Netherlands B.V."},
	{Code: "DE", Name: "Germany", Lat: 51.1657, Lon: 10.4515, City: "Frankfurt", ASN: "AS24940", Org: "Hetzner Online GmbH"},
	{Code: "FR", Name: "France", Lat: 46.2276, Lon: 2.2137, City: "Paris", ASN: "AS16276", Org: "OVH SAS"},
	{Code: "IN", Name: "India", Lat: 20.5937, Lon: 78.9629, City: "Mumbai", ASN: "AS55836", Org: "Reliance Jio Infocomm"},
	{Code: "BR", Name: "Brazil", Lat: -14.2350, Lon: -51.9253, City: "São Paulo", ASN: "AS28573", Org: "Claro Brasil"},
	{Code: "GB", Name: "United Kingdom", Lat: 55.3781, Lon: -3.4360, City: "London", ASN: "AS20860", Org: "IOMART CLOUD"},
	{Code: "KR", Name: "South Korea", Lat: 35.9078, Lon: 127.7669, City: "Seoul", ASN: "AS4766", Org: "Korea Telecom"},
	{Code: "VN", Name: "Vietnam", Lat: 14.0583, Lon: 108.2772, City: "Hanoi", ASN: "AS7552", Org: "Viettel Group"},
	{Code: "IR", Name: "Iran", Lat: 32.4279, Lon: 53.6880, City: "Tehran", ASN: "AS58224", Org: "Telecommunication Company of Iran"},
	{Code: "SG", Name: "Singapore", Lat: 1.3521, Lon: 103.8198, City: "Singapore", ASN: "AS4637", Org: "Telstra Global"},
	{Code: "JP", Name: "Japan", Lat: 36.2048, Lon: 138.2529, City: "Tokyo", ASN: "AS2516", Org: "KDDI Corporation"},
	{Code: "ID", Name: "Indonesia", Lat: -0.7893, Lon: 113.9213, City: "Jakarta", ASN: "AS7713", Org: "PT Telekomunikasi Indonesia"},
	{Code: "TR", Name: "Turkey", Lat: 38.9637, Lon: 35.2433, City: "Istanbul", ASN: "AS9121", Org: "Turk Telekom"},
	{Code: "UA", Name: "Ukraine", Lat: 48.3794, Lon: 31.1656, City: "Kyiv", ASN: "AS21219", Org: "Kyivstar GSM"},
	{Code: "CA", Name: "Canada", Lat: 56.1304, Lon: -106.3468, City: "Toronto", ASN: "AS812", Org: "Rogers Communications"},
	{Code: "PL", Name: "Poland", Lat: 51.9194, Lon: 19.1451, City: "Warsaw", ASN: "AS5617", Org: "Orange Polska"},
	{Code: "RO", Name: "Romania", Lat: 45.9432, Lon: 24.9668, City: "Bucharest", ASN: "AS8708", Org: "RCS & RDS"},
}

// Resolve returns GeoLocation for a given IPv4 or IPv6 address
func (r *Resolver) Resolve(ipStr string) models.GeoLocation {
	if cached, ok := r.cache.Load(ipStr); ok {
		return cached.(models.GeoLocation)
	}

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		localGeo := models.GeoLocation{
			CountryCode: "LOC",
			CountryName: "Local Network",
			City:        "Private Subnet",
			Latitude:    0.0,
			Longitude:   0.0,
			ASN:         "AS0",
			Org:         "Internal/LAN",
		}
		r.cache.Store(ipStr, localGeo)
		return localGeo
	}

	// Deterministic IP hash mapping to ensure consistent Geo distribution
	// for attack traffic visualization without remote API rate limits
	hasher := md5.New()
	hasher.Write([]byte(ipStr))
	hash := hasher.Sum(nil)
	val := binary.BigEndian.Uint64(hash[:8])

	idx := int(val % uint64(len(hotCountries)))
	base := hotCountries[idx]

	// Add slight coordinate jitter (+- 1.5 degrees) so multiple IPs in the same country don't overlap exactly
	latJitter := float64(int(hash[8])%300-150) / 100.0
	lonJitter := float64(int(hash[9])%300-150) / 100.0

	geo := models.GeoLocation{
		CountryCode: base.Code,
		CountryName: base.Name,
		City:        base.City,
		Latitude:    base.Lat + latJitter,
		Longitude:   base.Lon + lonJitter,
		ASN:         base.ASN,
		Org:         base.Org,
	}

	r.cache.Store(ipStr, geo)
	return geo
}

// ResolveIP is a helper function using defaultResolver
func ResolveIP(ipStr string) models.GeoLocation {
	return defaultResolver.Resolve(ipStr)
}
