package store

import (
	"sync"

	"sec_dash/backend/internal/model"
)

// Memory is a Persister that keeps auxiliary documents in process memory only.
// It is used when no MongoDB is configured (development / demo).
type Memory struct {
	mu   sync.Mutex
	docs map[string]map[string]map[string]interface{}
}

func NewMemory() *Memory {
	return &Memory{docs: map[string]map[string]map[string]interface{}{}}
}

func (m *Memory) Insert([]*model.Event) error       { return nil }
func (m *Memory) Load(int) ([]*model.Event, error)  { return nil, nil }
func (m *Memory) UpdateGeo(string, model.Geo) error { return nil }
func (m *Memory) Close() error                      { return nil }

func (m *Memory) PutDoc(coll, key string, doc map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.docs[coll] == nil {
		m.docs[coll] = map[string]map[string]interface{}{}
	}
	m.docs[coll][key] = doc
	return nil
}

func (m *Memory) DelDoc(coll, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.docs[coll], key)
	return nil
}

func (m *Memory) ListDocs(coll string) ([]map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []map[string]interface{}
	for _, d := range m.docs[coll] {
		out = append(out, d)
	}
	return out, nil
}
