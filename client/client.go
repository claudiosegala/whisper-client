package client

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/labbsr0x/whisper-client/misc"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	"github.com/labbsr0x/goh/gohtypes"

	"github.com/labbsr0x/whisper-client/config"
	"golang.org/x/oauth2"
)

// InitFromConfig initialize a whisper client from flags
func (client *WhisperClient) InitFromConfig(config *config.Config) *WhisperClient {
	client.hydraClient = new(hydraClient).initHydraClient(config.HydraAdminURL.String(), config.HydraPublicURL.String(), config.ClientID, config.ClientSecret, config.Scopes, config.RedirectURIs)
	client.isPublic = len(strings.ReplaceAll(config.ClientSecret, " ", "")) == 0

	return client
}

// InitFromParams initializes a whisper client from normal params
func (client *WhisperClient) InitFromParams(whisperURL, clientID, clientSecret string, scopes, redirectURIs []string) *WhisperClient {
	hydraAdminURL, hydraPublicURL := misc.RetrieveHydraURLs(whisperURL)

	whisperURI, err := url.Parse(whisperURL)
	gohtypes.PanicIfError("Invalid whisper url", 500, err)
	hydraAdminURI, err := url.Parse(hydraAdminURL)
	gohtypes.PanicIfError("Invalid hydra admin url", 500, err)
	hydraPublicURI, err := url.Parse(hydraPublicURL)
	gohtypes.PanicIfError("Invalid hydra public url", 500, err)

	return client.InitFromConfig(&config.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		WhisperURL:     whisperURI,
		HydraAdminURL:  hydraAdminURI,
		HydraPublicURL: hydraPublicURI,
		Scopes:         scopes,
		RedirectURIs:   redirectURIs,
	})
}

// CheckCredentials talks to the admin service to check wheather the client_id should be created and fires a client credentials flow accordingly (if pkce, client credentials flow is not fired)
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.getHydraOAuth2Client()

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.createOAuth2Client()
	}

	if err == nil {
		if hc.Scopes != strings.Join(client.scopes, " ") || !reflect.DeepEqual(hc.RedirectURIs, client.RedirectURIs) {
			_, err = client.updateOAuth2Client()
		}

		if err == nil && !client.isPublic {
			t, err = client.DoClientCredentialsFlow()
		}
	}

	return t, err
}

// GetTokenAsJSONStr stores the token in the environment variables as a json string
func (client *WhisperClient) GetTokenAsJSONStr(t *oauth2.Token) string {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.Encode(t)
	return buf.String()
}

// GetMuxSecurityMiddleware verifies if the client is authorized to make this request
func (client *WhisperClient) GetMuxSecurityMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string
			var token Token
			var err error

			if tokenString, err = getAccessTokenFromRequest(r); err == nil {
				if token, err = client.IntrospectToken(tokenString); err == nil {
					if token.Active {
						newR := r.WithContext(context.WithValue(r.Context(), TokenKey, token))
						next.ServeHTTP(w, newR)
						return
					}
				}
			}
			gohtypes.PanicIfError("Unauthorized user", 401, err)
		})
	}
}
