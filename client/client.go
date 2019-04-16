package client

import (
	"bytes"
	"encoding/json"

	"github.com/abilioesteves/whisper-client/config"
	"github.com/abilioesteves/whisper-client/hydra"
	"golang.org/x/oauth2"
)

// WhisperClient holds the info and structures a whisper client must
type WhisperClient struct {
	*config.Flags
	HydraClient *hydra.Client
}

// InitFromFlags initialize a whisper client from flags
func (client *WhisperClient) InitFromFlags(flags *config.Flags) *WhisperClient {
	client.Flags = flags
	client.HydraClient = new(hydra.Client).Init(flags.HydraAdminURL, flags.HydraPublicURL, flags.ClientID, flags.ClientSecret, client.Scopes, flags.RedirectURIs)

	return client
}

// InitFromParams initializes a whisper client from normal params
func (client *WhisperClient) InitFromParams(hydraAdminURL, hydraPublicURL, clientID, clientSecret string, scopes []string) *WhisperClient {
	return client.InitFromFlags(&config.Flags{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		Scopes:         scopes,
	})
}

// InitFromHydraClient initializes a whisper client from a hydra client
func (client *WhisperClient) InitFromHydraClient(hydraClient *hydra.Client) *WhisperClient {
	client.HydraClient = hydraClient
	client.Flags = &config.Flags{
		ClientID:       hydraClient.ClientID,
		ClientSecret:   hydraClient.ClientSecret,
		HydraAdminURL:  hydraClient.AdminURL.String(),
		HydraPublicURL: hydraClient.PublicURL.String(),
		Scopes:         hydraClient.Scopes,
		RedirectURIs:   hydraClient.RedirectURIs,
	}

	return client
}

// CheckCredentials talks to hydra and checks wheather the client_id should be created
func (client *WhisperClient) CheckCredentials() (t *oauth2.Token, err error) {
	hc, err := client.HydraClient.GetOAuth2Client()

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		hc, err = client.HydraClient.CreateOAuth2Client()
	}

	if err == nil {
		t, err = client.HydraClient.DoClientCredentialsFlow()
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
