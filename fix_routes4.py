import re

with open("backend/internal/api/routes.go", "r") as f:
    text = f.read()

# Routes setup
text = re.sub(r'r\.Post\("/ingest/cowrie".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/web".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/loki".*?\n', '', text)
text = re.sub(r'r\.Post\("/ingest/raw".*?\n', '', text)
text = re.sub(r'r\.Post\("/loki/api/v1/push".*?\n', '', text)
text = re.sub(r'r\.Get\("/alloy/config".*?\n', '', text)

# Remove parser
text = re.sub(r'parser\s+\*ingest\.Parser', '', text)
text = re.sub(r'parser:\s+parser,', '', text)
text = re.sub(r'"sec_dash/backend/internal/ingest"', '', text)

def empty_out_func(func_name, text):
    # match from func (s *Server) func_name { ... }
    # Since we can't reliably parse braces with regex, we will find the start, and replace it up to the next func
    # or EOF.
    return re.sub(r'func \(s \*Server\) ' + func_name + r'\(w http\.ResponseWriter, r \*http\.Request\) \{.*?(?=\nfunc |\Z)', 
                  'func (s *Server) ' + func_name + '(w http.ResponseWriter, r *http.Request) {}\n', text, flags=re.DOTALL)

text = empty_out_func('handleIngestCowrie', text)
text = empty_out_func('handleIngestWeb', text)
text = empty_out_func('handleIngestLoki', text)
text = empty_out_func('handleIngestRaw', text)
text = empty_out_func('handleAlloyConfig', text)

with open("backend/internal/api/routes.go", "w") as f:
    f.write(text)
