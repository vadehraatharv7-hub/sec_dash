import re

with open("backend/internal/api/routes.go", "r") as f:
    text = f.read()

# Routes setup
text = re.sub(r'r\.Post\("/ingest/cowrie".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/web".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/loki".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/raw".*?\n', '', text)
text = re.sub(r'r\.Post\("/loki/api/v1/push".*?\n', '', text)
text = re.sub(r'// Ingestion endpoints\n', '', text)
text = re.sub(r'// Standard Loki API alias.*?\n', '', text)

# Structs
text = re.sub(r'parser\s+\*ingest\.Parser\n\t', '', text)
text = re.sub(r'parser:\s+parser,\n\t\t', '', text)
text = re.sub(r'func NewServer\(storage \*db\.Storage, parser \*ingest\.Parser, hub \*Hub\) \*Server', 'func NewServer(storage *db.Storage, hub *Hub) *Server', text)
text = re.sub(r'"sec_dash/backend/internal/ingest"\n', '', text)

funcs = ['handleIngestCowrie', 'handleIngestWeb', 'handleIngestLoki', 'handleIngestRaw', 'handleAlloyConfig']
for fn in funcs:
    text = re.sub(r'func \(s \*Server\) ' + fn + r'\(w http.ResponseWriter, r \*http\.Request\) \{.*?^\}', 'func (s *Server) ' + fn + '(w http.ResponseWriter, r *http.Request) {}', text, flags=re.DOTALL | re.MULTILINE)

with open("backend/internal/api/routes.go", "w") as f:
    f.write(text)

