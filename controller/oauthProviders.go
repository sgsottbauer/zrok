package controller

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti/zrok/controller/config"
	"github.com/openziti/zrok/rest_model_zrok"
	"github.com/openziti/zrok/rest_server_zrok/operations/account"
)

type oauthProvidersHandler struct {
	cfg *config.Config
}

func newOauthProvidersHandler(cfg *config.Config) *oauthProvidersHandler {
	return &oauthProvidersHandler{cfg: cfg}
}

func (h *oauthProvidersHandler) Handle(params account.OauthProvidersParams) middleware.Responder {
	// Return empty list if OAuth is not configured or disabled
	if h.cfg.OAuth == nil || !h.cfg.OAuth.Enabled {
		return account.NewOauthProvidersOK().WithPayload([]*rest_model_zrok.OauthProvider{})
	}

	// Build list of providers
	providers := make([]*rest_model_zrok.OauthProvider, 0, len(h.cfg.OAuth.Providers))
	for _, providerCfg := range h.cfg.OAuth.Providers {
		provider := &rest_model_zrok.OauthProvider{
			Name:              providerCfg.Name,
			Type:              providerCfg.Type,
			AllowRegistration: providerCfg.AllowRegistration,
		}
		providers = append(providers, provider)
	}

	return account.NewOauthProvidersOK().WithPayload(providers)
}
