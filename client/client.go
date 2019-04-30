package client

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"

	"github.com/labbsr0x/whisper-client/config"
	"github.com/labbsr0x/whisper-client/hydra"
	"golang.org/x/oauth2"
)

// WhisperClient holds the info and structures a whisper client must
type WhisperClient struct {
	*config.Flags
	hydraClient *hydra.Client
}

// InitFromFlags initialize a whisper client from flags
func (client *WhisperClient) InitFromFlags(flags *config.Flags) *WhisperClient {
	client.Flags = flags
	client.hydraClient = new(hydra.Client).Init(flags.HydraAdminURL.String(), flags.HydraPublicURL.String(), flags.ClientID, flags.ClientSecret, client.Scopes, flags.RedirectURIs)

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

// InitFromHydraClient initializes a whisper client from a hydra client
func (client *WhisperClient) InitFromHydraClient(hydraClient *hydra.Client) *WhisperClient {
	client.hydraClient = hydraClient
	client.Flags = &config.Flags{
		ClientID:       hydraClient.ClientID,
		ClientSecret:   hydraClient.ClientSecret,
		HydraAdminURL:  hydraClient.Admin.BaseURL,
		HydraPublicURL: hydraClient.Public.BaseURL,
		Scopes:         hydraClient.Scopes,
		RedirectURIs:   hydraClient.RedirectURIs,
	}

	return client
}

// CheckCredentials talks to hydra to check wheather the client_id should be created and fires a client credentials flow accordingly
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.hydraClient.GetOAuth2Client()

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.hydraClient.CreateOAuth2Client()
	}

	if err == nil {
		if hc.Scopes != strings.Join(client.Scopes, " ") || !reflect.DeepEqual(hc.RedirectURIs, client.RedirectURIs) {
			_, err = client.hydraClient.UpdateOAuth2Client()
		}

		if err == nil {
			t, err = client.hydraClient.DoClientCredentialsFlow()
		}
	}

	return t, err
}

// GetOAuth2Client gets an oauth2 client to fire authorization flows
func (client *WhisperClient) GetOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
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

// IntrospectToken gets token information from
func (client *WhisperClient) IntrospectToken(token string) (hydra.Token, error) {
	return client.hydraClient.IntrospectToken(token)
}

// GetTokenAsJSONStr stores the token in the environment variables as a json string
func (client *WhisperClient) GetTokenAsJSONStr(t *oauth2.Token) string {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.Encode(t)
	return buf.String()
}
