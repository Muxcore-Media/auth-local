package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"golang.org/x/crypto/bcrypt"
)

type Module struct {
	store *Store
}

func NewModule() *Module {
	return &Module{store: NewStore()}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           "auth-local",
		Name:         "Local Auth",
		Version:      "1.0.0",
		Kind:         contracts.ModuleKindAuth,
		Description:  "Local accounts and API token authentication",
		Author:       "MuxCore",
		Capabilities: []string{"auth.local", "auth.api-tokens"},
	}
}

func (m *Module) Init(ctx context.Context) error  { return nil }
func (m *Module) Start(ctx context.Context) error  { return nil }
func (m *Module) Stop(ctx context.Context) error   { return nil }
func (m *Module) Health(ctx context.Context) error { return nil }

func (m *Module) Authenticate(ctx context.Context, credentials any) (contracts.Session, error) {
	cred, ok := credentials.(Credentials)
	if !ok {
		return contracts.Session{}, fmt.Errorf("invalid credentials type")
	}

	switch {
	case cred.Password != "":
		return m.authenticatePassword(ctx, cred.Username, cred.Password)
	case cred.Token != "":
		return m.authenticateToken(ctx, cred.Token)
	default:
		return contracts.Session{}, fmt.Errorf("no credentials provided")
	}
}

func (m *Module) Validate(ctx context.Context, token string) (contracts.Session, error) {
	return m.store.ValidateToken(token)
}

func (m *Module) Revoke(ctx context.Context, token string) error {
	return m.store.RevokeToken(token)
}

func (m *Module) CreateAccount(ctx context.Context, username, password string, roles []string) (*Account, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	account := &Account{
		ID:           newID(),
		Username:     username,
		PasswordHash: string(hash),
		Roles:        roles,
		CreatedAt:    time.Now(),
	}

	if err := m.store.CreateAccount(account); err != nil {
		return nil, err
	}
	return account, nil
}

func (m *Module) CreateAPIToken(ctx context.Context, username, label string) (*Token, error) {
	account, err := m.store.GetAccount(username)
	if err != nil {
		return nil, err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	token := &Token{
		ID:        newID(),
		AccountID: account.ID,
		Token:     "mxc_" + hex.EncodeToString(tokenBytes),
		Label:     label,
		CreatedAt: time.Now(),
	}

	if err := m.store.CreateToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

func (m *Module) authenticatePassword(ctx context.Context, username, password string) (contracts.Session, error) {
	account, err := m.store.GetAccount(username)
	if err != nil {
		return contracts.Session{}, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		return contracts.Session{}, fmt.Errorf("invalid credentials")
	}

	return contracts.Session{
		UserID:      account.ID,
		Username:    account.Username,
		Roles:       account.Roles,
		Permissions: []string{"*"},
	}, nil
}

func (m *Module) authenticateToken(ctx context.Context, rawToken string) (contracts.Session, error) {
	return m.store.ValidateToken(rawToken)
}

type Credentials struct {
	Username string
	Password string
	Token    string
}

type Account struct {
	ID           string
	Username     string
	PasswordHash string
	Roles        []string
	CreatedAt    time.Time
}

type Token struct {
	ID        string
	AccountID string
	Token     string
	Label     string
	CreatedAt time.Time
}

type Store struct {
	mu       sync.RWMutex
	accounts map[string]*Account  // by username
	tokens   map[string]*Token    // by token value
}

func NewStore() *Store {
	return &Store{
		accounts: make(map[string]*Account),
		tokens:   make(map[string]*Token),
	}
}

func (s *Store) CreateAccount(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[a.Username]; exists {
		return fmt.Errorf("account %q already exists", a.Username)
	}
	s.accounts[a.Username] = a
	return nil
}

func (s *Store) GetAccount(username string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.accounts[username]
	if !ok {
		return nil, fmt.Errorf("account %q not found", username)
	}
	return a, nil
}

func (s *Store) CreateToken(t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[t.Token] = t
	return nil
}

func (s *Store) ValidateToken(rawToken string) (contracts.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[rawToken]
	if !ok {
		return contracts.Session{}, fmt.Errorf("invalid token")
	}

	// Look up the account
	for _, a := range s.accounts {
		if a.ID == t.AccountID {
			return contracts.Session{
				UserID:      a.ID,
				Username:    a.Username,
				Roles:       a.Roles,
				Permissions: []string{"*"},
				Token:       rawToken,
			}, nil
		}
	}
	return contracts.Session{}, fmt.Errorf("account not found for token")
}

func (s *Store) RevokeToken(rawToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, rawToken)
	return nil
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
