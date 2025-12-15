package controller

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti/zrok/controller/config"
	"github.com/openziti/zrok/controller/oauth"
	"github.com/openziti/zrok/controller/store"
	"github.com/openziti/zrok/rest_server_zrok/operations/account"
	"github.com/sirupsen/logrus"
)

type oauthCallbackHandler struct {
	cfg      *config.Config
	oauthMgr *oauth.Manager
}

func newOauthCallbackHandler(cfg *config.Config, mgr *oauth.Manager) *oauthCallbackHandler {
	return &oauthCallbackHandler{
		cfg:      cfg,
		oauthMgr: mgr,
	}
}

func (h *oauthCallbackHandler) Handle(params account.OauthCallbackParams) middleware.Responder {
	// Handle OAuth errors
	if params.Error != nil {
		logrus.Errorf("OAuth error from provider '%s': %s", params.Provider, *params.Error)
		return account.NewOauthCallbackBadRequest()
	}

	// Exchange authorization code for tokens and user info
	session, err := h.oauthMgr.HandleCallback(params.Provider, params.Code, params.State)
	if err != nil {
		logrus.Errorf("OAuth callback error for provider '%s': %v", params.Provider, err)
		return account.NewOauthCallbackInternalServerError()
	}

	// Start database transaction
	tx, err := str.Begin()
	if err != nil {
		logrus.Errorf("error starting transaction: %v", err)
		return account.NewOauthCallbackInternalServerError()
	}
	defer func() { _ = tx.Rollback() }()

	// Try to find existing OAuth account
	existingAccount, err := str.FindAccountWithOAuth(session.Provider, session.Subject, tx)

	if err == nil {
		// LOGIN FLOW: Account exists
		logrus.Infof("OAuth login successful for existing account: %s (provider: %s)", existingAccount.Email, session.Provider)

		return account.NewOauthCallbackOK().WithPayload(&account.OauthCallbackOKBody{
			AccountToken: existingAccount.Token,
			Email:        existingAccount.Email,
		})
	}

	// REGISTRATION FLOW: Account doesn't exist
	// Get provider configuration
	provider, err := h.oauthMgr.GetProvider(params.Provider)
	if err != nil {
		logrus.Errorf("provider not found: %s", params.Provider)
		return account.NewOauthCallbackBadRequest()
	}

	providerCfg := provider.GetConfig()

	// Check if registration is allowed
	if !providerCfg.AllowRegistration {
		logrus.Warnf("OAuth registration not allowed for provider: %s", params.Provider)
		return account.NewOauthCallbackBadRequest()
	}

	// Verify email is verified (if required)
	if providerCfg.TrustEmailVerified && !session.EmailVerified {
		logrus.Warnf("email not verified for OAuth user: %s (provider: %s)", session.Email, params.Provider)
		return account.NewOauthCallbackBadRequest()
	}

	// Check if email is already used by a password-based account
	existingPasswordAccount, err := str.FindAccountWithEmail(session.Email, tx)
	if err == nil && existingPasswordAccount != nil {
		logrus.Errorf("email already in use by password account: %s", session.Email)
		return account.NewOauthCallbackBadRequest()
	}

	// Create new OAuth account (NO INVITE TOKEN REQUIRED)
	accountToken, err := CreateToken()
	if err != nil {
		logrus.Errorf("error creating account token: %v", err)
		return account.NewOauthCallbackInternalServerError()
	}

	oauthAccount := &store.Account{
		Email:         session.Email,
		Token:         accountToken,
		OauthProvider: &session.Provider,
		OauthSubject:  &session.Subject,
		Limitless:     false, // Apply default limits
	}

	if _, err := str.CreateOAuthAccount(oauthAccount, tx); err != nil {
		logrus.Errorf("error creating OAuth account: %v", err)
		return account.NewOauthCallbackInternalServerError()
	}

	if err := tx.Commit(); err != nil {
		logrus.Errorf("error committing OAuth account: %v", err)
		return account.NewOauthCallbackInternalServerError()
	}

	logrus.Infof("created new OAuth account: %s (provider: %s)", session.Email, session.Provider)

	return account.NewOauthCallbackOK().WithPayload(&account.OauthCallbackOKBody{
		AccountToken: oauthAccount.Token,
		Email:        oauthAccount.Email,
	})
}
