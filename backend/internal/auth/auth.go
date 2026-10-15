// Package auth implements dashboard accounts: bcrypt-hashed passwords and
// signed, expiring session tokens.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sec_dash/backend/internal/store"
)

const (
	usersColl    = "dash_users"
	settingsColl = "dash_settings"
	SessionTTL   = 12 * time.Hour
)

type User struct {
	Name string
	Role string
	hash []byte
}

type Manager struct {
	p      store.Persister
	mu     sync.RWMutex
	users  map[string]*User
	secret []byte
}

// New loads accounts and the signing secret (created on first run and kept in
// the database so sessions survive restarts).
func New(p store.Persister) *Manager {
	m := &Manager{p: p, users: map[string]*User{}}
	if p != nil {
		if docs, err := p.ListDocs(usersColl); err == nil {
			for _, d := range docs {
				name, _ := d["username"].(string)
				h, _ := d["hash"].(string)
				role, _ := d["role"].(string)
				if name != "" && h != "" {
					m.users[name] = &User{Name: name, Role: role, hash: []byte(h)}
				}
			}
		}
		if docs, err := p.ListDocs(settingsColl); err == nil {
			for _, d := range docs {
				if d["_id"] == "session_secret" {
					if s, _ := d["value"].(string); s != "" {
						m.secret, _ = hex.DecodeString(s)
					}
				}
			}
		}
	}
	if len(m.secret) < 32 {
		m.secret = make([]byte, 32)
		_, _ = rand.Read(m.secret)
		if p != nil {
			_ = p.PutDoc(settingsColl, "session_secret", map[string]interface{}{"value": hex.EncodeToString(m.secret)})
		}
	}
	return m
}

// HasUsers reports whether any account exists (which turns login on).
func (m *Manager) HasUsers() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users) > 0
}

// SetPassword creates or updates an account.
func (m *Manager) SetPassword(name, password, role string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(password) < 8 {
		return errors.New("username required and password must be at least 8 characters")
	}
	if role == "" {
		role = "admin"
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.users[name] = &User{Name: name, Role: role, hash: h}
	m.mu.Unlock()
	if m.p != nil {
		return m.p.PutDoc(usersColl, name, map[string]interface{}{
			"username": name, "hash": string(h), "role": role, "updated": time.Now().UTC().Format(time.RFC3339),
		})
	}
	return nil
}

var dummy, _ = bcrypt.GenerateFromPassword([]byte("x"), bcrypt.DefaultCost)

// Verify checks a username/password. It always spends one bcrypt comparison so
// timing does not reveal whether the user exists.
func (m *Manager) Verify(name, password string) (*User, bool) {
	m.mu.RLock()
	u := m.users[strings.TrimSpace(name)]
	m.mu.RUnlock()
	if u == nil {
		_ = bcrypt.CompareHashAndPassword(dummy, []byte(password))
		return nil, false
	}
	return u, bcrypt.CompareHashAndPassword(u.hash, []byte(password)) == nil
}

func (m *Manager) sign(msg string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Issue returns a signed session token "user.expiry.signature".
func (m *Manager) Issue(u *User) (string, time.Time) {
	exp := time.Now().Add(SessionTTL)
	body := base64.RawURLEncoding.EncodeToString([]byte(u.Name)) + "." + strconv.FormatInt(exp.Unix(), 10)
	return "s1." + body + "." + m.sign(body), exp
}

// Check validates a session token and returns the account name.
func (m *Manager) Check(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 || parts[0] != "s1" {
		return "", false
	}
	body := parts[1] + "." + parts[2]
	if subtle.ConstantTimeCompare([]byte(m.sign(body)), []byte(parts[3])) != 1 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	name, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	m.mu.RLock()
	_, ok := m.users[string(name)]
	m.mu.RUnlock()
	return string(name), ok
}
