package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	"github.com/labbsr0x/goh/gohtypes"

	"github.com/labbsr0x/whisper-client/config"
	"github.com/labbsr0x/whisper-client/hydra"
	"golang.org/x/oauth2"
)

// WhisperClient holds the info and structures a whisper client must
type WhisperClient struct {
	*hydra.Client
	isPublic       bool
	HydraAdminURL  *url.URL
	HydraPublicURL *url.URL
}

type key string

const (
	// TokenKey defines the key that shall be used to store a token in a requests' context
	TokenKey key = "token"
)

// InitFromFlags initialize a whisper client from flags
func (client *WhisperClient) InitFromFlags(flags *config.Flags) *WhisperClient {
	client.Client = new(hydra.Client).Init(flags.HydraAdminURL.String(), flags.HydraPublicURL.String(), flags.ClientID, flags.ClientSecret, client.Scopes, flags.RedirectURIs)
	client.isPublic = len(strings.ReplaceAll(flags.ClientSecret, " ", "")) == 0
	return client
}

// InitFromParams initializes a whisper client from normal params
func (client *WhisperClient) InitFromParams(hydraAdminURL, hydraPublicURL, clientID, clientSecret string, scopes, redirectURIs []string) *WhisperClient {
	adminURI, err := url.Parse(hydraAdminURL)
	gohtypes.PanicIfError("Invalid whisper admin url", 500, err)
	publicURI, err := url.Parse(hydraPublicURL)
	gohtypes.PanicIfError("Invalid whisper public url", 500, err)

	return client.InitFromFlags(&config.Flags{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		HydraAdminURL:  adminURI,
		HydraPublicURL: publicURI,
		Scopes:         scopes,
		RedirectURIs:   redirectURIs,
	})
}

// CheckCredentials talks to hydra to check wheather the client_id should be created and fires a client credentials flow accordingly
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.GetHydraOAuth2Client()

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.CreateOAuth2Client()
	}

	if err == nil {
		if hc.Scopes != strings.Join(client.Scopes, " ") || !reflect.DeepEqual(hc.RedirectURIs, client.RedirectURIs) {
			_, err = client.UpdateOAuth2Client()
		}

		if err == nil && !client.isPublic {
			t, err = client.DoClientCredentialsFlow()
		}
	}

	return t, err
}

// GetXOAuth2Client gets an oauth2 client to fire authorization flows
func (client *WhisperClient) GetXOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
	authURL, _ := client.HydraPublicURL.Parse("/oauth2/auth")
	tokenURL, _ := client.HydraPublicURL.Parse("/oauth2/token")

	return &oauth2.Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
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
			var token hydra.Token
			var err error

			if tokenString, err = client.GetAccessTokenFromRequest(r); err == nil {
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

// GetAccessTokenFromRequest is a helper method to recover an Access Token from a http request
func (client *WhisperClient) GetAccessTokenFromRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authURLParam := r.URL.Query().Get("token")
	var t string

	if len(authHeader) == 0 && len(authURLParam) == 0 {
		return "", fmt.Errorf("No Authorization Header or URL Param found")
	}

	if len(authHeader) > 0 {
		data := strings.Split(authHeader, " ")

		if len(data) != 2 {
			return "", fmt.Errorf("Bad Authorization Header")
		}

		t = data[0]

		if len(t) == 0 || t != "Bearer" {
			return "", fmt.Errorf("No Bearer Token found")
		}

		t = data[1]

	} else {
		t = authURLParam
	}

	if len(t) == 0 {
		return "", fmt.Errorf("Bad Authorization Token")
	}

	return t, nil
}
