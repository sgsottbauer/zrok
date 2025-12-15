package oauth

import (
	"context"
	"time"

	"github.com/openziti/zrok/controller/config"
	"github.com/pkg/errors"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// OIDCProvider wraps an OIDC relying party
type OIDCProvider struct {
	config       *config.OAuthProviderConfig
	relyingParty rp.RelyingParty
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(cfg *config.OAuthProviderConfig, callbackURL string) (*OIDCProvider, error) {
	if cfg == nil {
		return nil, errors.New("provider config is nil")
	}

	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required for OIDC provider")
	}

	if cfg.ClientID == "" {
		return nil, errors.New("client ID is required for OIDC provider")
	}

	if cfg.ClientSecret == "" {
		return nil, errors.New("client secret is required for OIDC provider")
	}

	// Default scopes if not provided
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}
	}

	// Create OIDC relying party options
	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithPKCE(nil), // PKCE will be generated automatically
	}

	// Create OIDC relying party
	relyingParty, err := rp.NewRelyingPartyOIDC(
		context.Background(),
		cfg.Issuer,
		cfg.ClientID,
		cfg.ClientSecret,
		callbackURL,
		scopes,
		options...,
	)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to create OIDC relying party for issuer '%s'", cfg.Issuer)
	}

	return &OIDCProvider{
		config:       cfg,
		relyingParty: relyingParty,
	}, nil
}

// GetAuthURL generates the authorization URL
func (p *OIDCProvider) GetAuthURL(state string) string {
	return rp.AuthURL(state, p.relyingParty)
}

// ExchangeCode exchanges an authorization code for tokens and user info
func (p *OIDCProvider) ExchangeCode(code string) (*oidc.Tokens[*oidc.IDTokenClaims], *oidc.UserInfo, error) {
	// Exchange code for tokens
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](
		context.Background(),
		code,
		p.relyingParty,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "code exchange failed")
	}

	// Get user info
	userInfo, err := rp.Userinfo[*oidc.UserInfo](
		context.Background(),
		tokens.AccessToken,
		tokens.TokenType,
		tokens.IDTokenClaims.Subject,
		p.relyingParty,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get user info")
	}

	return tokens, userInfo, nil
}

// GetConfig returns the provider configuration
func (p *OIDCProvider) GetConfig() *config.OAuthProviderConfig {
	return p.config
}
