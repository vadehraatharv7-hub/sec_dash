import re

with open("backend/internal/api/routes.go", "r") as f:
    content = f.read()

# Add import
if '"github.com/oschwald/geoip2-golang"' not in content:
    content = content.replace('"net/http"', '"net/http"\n\t"net"\n\t"github.com/oschwald/geoip2-golang"')

# Add geoDB to Server struct
content = content.replace("startTime time.Time", "startTime time.Time\n\tgeoDB     *geoip2.Reader")

# Open GeoDB in NewServer
new_server_code = """func NewServer(storage *db.Storage, hub *Hub) *Server {
	var geo *geoip2.Reader
	dbPath := "GeoLite2-City.mmdb"
	if _, err := os.Stat("/home/azureuser/app/backend/GeoLite2-City.mmdb"); err == nil {
		dbPath = "/home/azureuser/app/backend/GeoLite2-City.mmdb"
	} else if _, err := os.Stat("/tmp/GeoLite2-City.mmdb"); err == nil {
		dbPath = "/tmp/GeoLite2-City.mmdb"
	}
	
	geo, err := geoip2.Open(dbPath)
	if err != nil {
		log.Printf("Warning: Failed to open GeoIP DB at %s: %v", dbPath, err)
	} else {
		log.Printf("Successfully loaded local GeoIP database: %s", dbPath)
	}

	return &Server{
		storage:   storage,
		hub:       hub,
		analyst:   ai.NewAnalyst(storage),
		alerts:    alerts.NewEngine(storage),
		startTime: time.Now(),
		geoDB:     geo,
	}
}"""

content = re.sub(r"func NewServer.*?return &Server{.*?}", new_server_code, content, flags=re.DOTALL)

# Replace the IP-API loop inside handleIngestStream
old_ip_api = """			// Perform quick GeoIP lookup
			resp, err := http.Get("http://ip-api.com/json/" + v)
			if err == nil {
				defer resp.Body.Close()
				var geo struct {
					CountryCode string  `json:"countryCode"`
					CountryName string  `json:"country"`
					City        string  `json:"city"`
					Lat         float64 `json:"lat"`
					Lon         float64 `json:"lon"`
					Asn         string  `json:"as"`
					Org         string  `json:"org"`
				}
				if json.NewDecoder(resp.Body).Decode(&geo) == nil {
					ev.Geo.CountryCode = geo.CountryCode
					ev.Geo.CountryName = geo.CountryName
					ev.Geo.City = geo.City
					ev.Geo.Latitude = geo.Lat
					ev.Geo.Longitude = geo.Lon
					ev.Geo.ASN = geo.Asn
					ev.Geo.Org = geo.Org
				}
			}"""

new_geoip = """			// Perform local GeoIP lookup
			if s.geoDB != nil {
				ip := net.ParseIP(v)
				if ip != nil {
					record, err := s.geoDB.City(ip)
					if err == nil {
						ev.Geo.CountryCode = record.Country.IsoCode
						if val, ok := record.Country.Names["en"]; ok {
							ev.Geo.CountryName = val
						}
						if val, ok := record.City.Names["en"]; ok {
							ev.Geo.City = val
						}
						ev.Geo.Latitude = record.Location.Latitude
						ev.Geo.Longitude = record.Location.Longitude
					}
					
					// ASN is in a separate DB (GeoLite2-ASN), but for now we skip it
					// or use generic info. The map only requires Lat/Lon and Country.
				}
			}"""

content = content.replace(old_ip_api, new_geoip)

with open("backend/internal/api/routes.go", "w") as f:
    f.write(content)

print("routes.go patched")
