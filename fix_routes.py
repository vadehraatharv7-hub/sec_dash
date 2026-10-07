import re

with open("backend/internal/api/routes.go", "r") as f:
    content = f.read()

# Remove ingestion routes section entirely
content = re.sub(r'// Ingestion endpoints.*?// Dashboard analytics', '// Dashboard analytics', content, flags=re.DOTALL)

# Remove parser
content = re.sub(r'parser\s+\*ingest\.Parser\n\t', '', content)
content = re.sub(r'func NewServer\(storage \*db\.Storage, parser \*ingest\.Parser, hub \*Hub\) \*Server \{.*?\}',
                 '''func NewServer(storage *db.Storage, hub *Hub) *Server {
	return &Server{
		storage:   storage,
		hub:       hub,
		analyst:   ai.NewAnalyst(storage),
		alerts:    alerts.NewEngine(storage),
		startTime: time.Now(),
	}
}''', content, flags=re.DOTALL)
content = re.sub(r'"sec_dash/backend/internal/ingest"\n\t', '', content)

# Remove handlers: handleIngestCowrie, handleIngestWeb, handleIngestLoki, handleIngestRaw, handleAlloyConfig
# using simpler replacements
def remove_func(func_name, code):
    pattern = r'func \(s \*Server\) ' + func_name + r'\(.*?^}'
    return re.sub(pattern, '', code, flags=re.DOTALL | re.MULTILINE)

content = remove_func('handleIngestCowrie', content)
content = remove_func('handleIngestWeb', content)
content = remove_func('handleIngestLoki', content)
content = remove_func('handleIngestRaw', content)
content = remove_func('handleAlloyConfig', content)

with open("backend/internal/api/routes.go", "w") as f:
    f.write(content)

