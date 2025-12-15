package controller

import (
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti/zrok/controller/config"
	"github.com/openziti/zrok/controller/oauth"
	"github.com/openziti/zrok/rest_server_zrok/operations/account"
	"github.com/sirupsen/logrus"
)

type oauthAuthorizeHandler struct {
	cfg      *config.Config
	oauthMgr *oauth.Manager
}

func newOauthAuthorizeHandler(cfg *config.Config, mgr *oauth.Manager) *oauthAuthorizeHandler {
	return &oauthAuthorizeHandler{
		cfg:      cfg,
		oauthMgr: mgr,
	}
}

func (h *oauthAuthorizeHandler) Handle(params account.OauthAuthorizeParams) middleware.Responder {
	// Generate authorization URL
	authURL, err := h.oauthMgr.GetAuthorizationURL(params.Provider)
	if err != nil {
		logrus.Errorf("error generating OAuth authorization URL for provider '%s': %v", params.Provider, err)
		return account.NewOauthAuthorizeNotFound()
	}

	// Redirect to OAuth provider
	logrus.Infof("redirecting to OAuth provider '%s' for authorization", params.Provider)
	return middleware.ResponderFunc(func(w http.ResponseWriter, pr runtime.Producer) {
		w.Header().Set("Location", authURL)
		w.WriteHeader(http.StatusFound)
	})
}
