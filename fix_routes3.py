with open("backend/internal/api/routes.go", "r") as f:
    lines = f.readlines()

out = []
in_ingest = False
for line in lines:
    if line.startswith('func (s *Server) handleIngestCowrie'): in_ingest = True
    if line.startswith('func (s *Server) handleIngestWeb'): in_ingest = True
    if line.startswith('func (s *Server) handleIngestLoki'): in_ingest = True
    if line.startswith('func (s *Server) handleIngestRaw'): in_ingest = True
    if line.startswith('func (s *Server) handleAlloyConfig'): in_ingest = True

    if line.startswith('func (s *Server) handle') and not any(x in line for x in ['handleIngest', 'handleAlloyConfig']):
        in_ingest = False
    
    if 'r.Post("/ingest/' in line or 'r.Post("/loki/' in line:
        continue
    if 'parser   *ingest.Parser' in line:
        continue
    if 'parser:    parser,' in line:
        continue
    if '"sec_dash/backend/internal/ingest"' in line:
        continue
    if 'func NewServer(storage *db.Storage, parser *ingest.Parser, hub *Hub) *Server {' in line:
        line = 'func NewServer(storage *db.Storage, hub *Hub) *Server {\n'

    if not in_ingest:
        out.append(line)
        
with open("backend/internal/api/routes.go", "w") as f:
    f.writelines(out)

