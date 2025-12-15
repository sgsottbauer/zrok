package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openziti/zrok/controller/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// OAuthSession represents a successful OAuth authentication
type OAuthSession struct {
	Email         string
	EmailVerified bool
	Subject       string // OAuth subject (user ID from provider)
	Provider      string // Provider identifier
	UserInfo      *oidc.UserInfo
}

// StateToken represents the OAuth state parameter (CSRF protection)
type StateToken struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	jwt.RegisteredClaims
}

// Manager handles OAuth operations
type Manager struct {
	config         *config.OAuthConfig
	providers      map[string]*OIDCProvider
	stateTokens    map[string]*StateToken
	stateTokensMux sync.RWMutex
	signingKey     []byte
}

// NewManager creates a new OAuth manager
func NewManager(cfg *config.OAuthConfig) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("oauth config is nil")
	}

	if !cfg.Enabled {
		return nil, errors.New("oauth is not enabled")
	}

	if cfg.SigningKey == "" {
		return nil, errors.New("oauth signing key is required")
	}

	m := &Manager{
		config:      cfg,
		providers:   make(map[string]*OIDCProvider),
		stateTokens: make(map[string]*StateToken),
		signingKey:  []byte(cfg.SigningKey),
	}

	// Initialize OIDC providers
	for _, providerCfg := range cfg.Providers {
		callbackURL := fmt.Sprintf("%s/%s/callback", cfg.CallbackBaseURL, providerCfg.Name)

		provider, err := NewOIDCProvider(&providerCfg, callbackURL)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to initialize OIDC provider '%s'", providerCfg.Name)
		}

		m.providers[providerCfg.Name] = provider
		logrus.Infof("initialized OAuth provider: %s (%s)", providerCfg.Name, providerCfg.Issuer)
	}

	// Start state token cleanup goroutine
	go m.cleanupExpiredStateTokens()

	return m, nil
}

// GetProviders returns all configured providers
func (m *Manager) GetProviders() []config.OAuthProviderConfig {
	return m.config.Providers
}

// GetProvider returns a specific provider by name
func (m *Manager) GetProvider(name string) (*OIDCProvider, error) {
	provider, ok := m.providers[name]
	if !ok {
		return nil, errors.Errorf("provider '%s' not found", name)
	}
	return provider, nil
}

// GetAuthorizationURL generates an OAuth authorization URL with state token
func (m *Manager) GetAuthorizationURL(providerName string) (string, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	// Generate state token
	stateID, err := generateRandomString(32)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate state ID")
	}

	state := &StateToken{
		ID:        stateID,
		Provider:  providerName,
		CreatedAt: time.Now(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.getStateTokenLifetime())),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Sign state token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, state)
	stateString, err := token.SignedString(m.signingKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign state token")
	}

	// Store state token
	m.stateTokensMux.Lock()
	m.stateTokens[stateID] = state
	m.stateTokensMux.Unlock()

	// Get authorization URL from provider
	authURL := provider.GetAuthURL(stateString)

	logrus.Debugf("generated OAuth authorization URL for provider '%s'", providerName)
	return authURL, nil
}

// HandleCallback handles the OAuth callback
func (m *Manager) HandleCallback(providerName, code, stateString string) (*OAuthSession, error) {
	// Verify and parse state token
	state, err := m.verifyStateToken(stateString)
	if err != nil {
		return nil, errors.Wrap(err, "invalid state token")
	}

	// Verify provider matches
	if state.Provider != providerName {
		return nil, errors.Errorf("provider mismatch: expected '%s', got '%s'", state.Provider, providerName)
	}

	// Get provider
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens
	_, userInfo, err := provider.ExchangeCode(code)
	if err != nil {
		return nil, errors.Wrap(err, "failed to exchange authorization code")
	}

	// Extract email
	email := userInfo.Email
	if email == "" {
		return nil, errors.New("email not provided by OAuth provider")
	}

	// Extract subject
	subject := userInfo.Subject
	if subject == "" {
		return nil, errors.New("subject not provided by OAuth provider")
	}

	// Build provider identifier (format: "oidc:issuer-url")
	providerID := fmt.Sprintf("oidc:%s", provider.config.Issuer)

	session := &OAuthSession{
		Email:         email,
		EmailVerified: bool(userInfo.EmailVerified),
		Subject:       subject,
		Provider:      providerID,
		UserInfo:      userInfo,
	}

	// Remove used state token
	m.stateTokensMux.Lock()
	delete(m.stateTokens, state.ID)
	m.stateTokensMux.Unlock()

	logrus.Infof("OAuth callback successful for provider '%s', email: %s", providerName, email)
	return session, nil
}

// verifyStateToken verifies and parses a state token
func (m *Manager) verifyStateToken(stateString string) (*StateToken, error) {
	// Parse and verify JWT
	token, err := jwt.ParseWithClaims(stateString, &StateToken{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.signingKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to parse state token")
	}

	if !token.Valid {
		return nil, errors.New("invalid state token")
	}

	state, ok := token.Claims.(*StateToken)
	if !ok {
		return nil, errors.New("invalid state token claims")
	}

	// Check if state token exists in our store (prevents replay attacks)
	m.stateTokensMux.RLock()
	_, exists := m.stateTokens[state.ID]
	m.stateTokensMux.RUnlock()

	if !exists {
		return nil, errors.New("state token not found or already used")
	}

	return state, nil
}

// cleanupExpiredStateTokens periodically removes expired state tokens
func (m *Manager) cleanupExpiredStateTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.stateTokensMux.Lock()
		now := time.Now()
		for id, state := range m.stateTokens {
			if state.ExpiresAt != nil && state.ExpiresAt.Before(now) {
				delete(m.stateTokens, id)
				logrus.Debugf("cleaned up expired state token: %s", id)
			}
		}
		m.stateTokensMux.Unlock()
	}
}

// getStateTokenLifetime returns the state token lifetime from config or default
func (m *Manager) getStateTokenLifetime() time.Duration {
	if m.config.StateTokenLifetime > 0 {
		return m.config.StateTokenLifetime
	}
	return 10 * time.Minute // Default 10 minutes
}

// generateRandomString generates a random base64-encoded string
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
