package client

import (
	"github.com/abilioesteves/hydra-init-client/config"
	"github.com/abilioesteves/hydra-init-client/hydra"
)

// WhisperClient holds the info and structures a whisper client must
type WhisperClient struct {
	*config.Flags
	HydraClient *hydra.Client
}

// InitFromFlags initialize a whisper client from flags
func (client *WhisperClient) InitFromFlags(flags *config.Flags) *WhisperClient {
	client.HydraClient = new(hydra.Client).Init(flags.HydraAdminURL)

	return client
}

// CheckCredentials talks to hydra and checks wheather the client_id should be created
func (client *WhisperClient) CheckCredentials() error {
	hc, err := client.HydraClient.GetOAuth2Client(client.ClientID)

	if err != nil {
		panic(err)
	}

	if err == nil && hc == nil { // NOT FOUND; Client should be created
		client.HydraClient.CreateOAuth2Client(client.ClientID, client.ClientSecret)
	}

	return nil
}
