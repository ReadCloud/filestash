package plg_authenticate_openid

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	. "github.com/mickael-kerjean/filestash/server/common"
	"golang.org/x/oauth2"
)

func init() {
	Hooks.Register.AuthenticationMiddleware("openid", OpenID{})
}

type OpenID struct{}

func (this OpenID) Setup() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "openid",
			},
			{
				Name:        "OpenID Config URL",
				Type:        "text",
				ReadOnly:    false,
				Placeholder: "https://accounts.google.com/.well-known/openid-configuration",
				Required:    true,
			},
			{
				Name:        "Client ID",
				Type:        "text",
				ReadOnly:    false,
				Placeholder: "...",
				Required:    true,
			},
			{
				Name:        "Client Secret",
				Type:        "password",
				ReadOnly:    false,
				Placeholder: "...",
				Required:    true,
			},
			{
				Name:        "Scope",
				Type:        "text",
				ReadOnly:    false,
				Placeholder: "openid",
				Description: ``,
				Required:    true,
			},
			{
				Name:        "App Modules Required",
				Type:        "text",
				ReadOnly:    false,
				Placeholder: "S3FileBrowser",
				Description: ``,
				Required:    true,
			},
		},
	}
}

func (this OpenID) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	provider, err := oidc.NewProvider(req.Context(), idpParams["OpenID Config URL"])
	if err != nil {
		// handle error
	}
	queryParams := req.URL.Query()

	oauth2Config := oauth2.Config{
		ClientID:     idpParams["Client ID"],
		ClientSecret: idpParams["Client Secret"],
		RedirectURL:  fmt.Sprintf("https://%s/auth/", req.URL.Host),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: strings.Split(idpParams["Scope"], " "),
	}

	http.Redirect(res, req, oauth2Config.AuthCodeURL(queryParams.Get("state")), http.StatusFound)
	return nil
}

func (this OpenID) Callback(formData map[string]string, idpParams map[string]string, res http.ResponseWriter) (map[string]string, error) {
	v := make([]string, 0, len(formData))

	for _, value := range formData {
		v = append(v, value)
	}
	Log.Info(strings.Join(v, ", "))
	return nil, ErrNotImplemented
}
