package client

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"

	"github.com/sirupsen/logrus"

	"github.com/labbsr0x/goh/gohclient"
)

// HydraClient holds data and methods to communicate with an hydra service instance
type HydraClient struct {
	Public       *gohclient.Default
	Admin        *gohclient.Default
	Scopes       []string
	ClientID     string
	ClientSecret string
	RedirectURIs []string

	tokenEndpointAuthMethod string
	grantTypes              []string
}

// initHydraClient initializes a hydra client
func (client *HydraClient) initHydraClient(hydraAdminURL, hydraPublicURL, clientID, clientSecret string, scopes, redirectURIs []string) *HydraClient {
	var err error
	client.Public, err = gohclient.New(nil, hydraPublicURL)
	gohtypes.PanicIfError("Invalid HydraPublicURL", 500, err)
	client.Admin, err = gohclient.New(nil, hydraAdminURL)
	gohtypes.PanicIfError("Invalid HydraAdminURL", 500, err)
	client.Public.ContentType = "application/json"
	client.Admin.ContentType = "application/json"
	client.Public.Accept = "application/json"
	client.Admin.Accept = "application/json"

	client.Scopes = scopes
	client.ClientID = clientID
	client.ClientSecret = clientSecret
	client.RedirectURIs = redirectURIs

	client.tokenEndpointAuthMethod = "none"
	client.grantTypes = []string{"authorization_code", "refresh_token"}

	if len(strings.ReplaceAll(client.ClientSecret, " ", "")) > 0 { // a non public client can perform client_credentials grant type and should inform the secret on all transctions
		client.tokenEndpointAuthMethod = "client_secret_post"
		client.grantTypes = append(client.grantTypes, "client_credentials")
	}
	return client
}

// getHydraOAuth2Client calls hydra to get a clients information
func (client *HydraClient) getHydraOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/clients/", client.ClientID)

	logrus.Debugf("GetOAuth2Client - GET '%v'", client.ClientID)
	resp, data, err := client.Admin.Get(p)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// createOAuth2Client calls hydra to create an oauth2 client
func (client *HydraClient) createOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/clients")
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                client.ClientID,
			ClientSecret:            client.ClientSecret,
			TokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
			Scopes:                  strings.Join(client.Scopes, " "),
			GrantTypes:              client.grantTypes,
			RedirectURIs:            client.RedirectURIs,
		})

	logrus.Debugf("CreateOAuth2Client - POST payload: '%v'", payloadData)
	resp, data, err := client.Admin.Post(p, payloadData)
	if err == nil {
		if resp != nil {
			if resp.StatusCode == 201 {
				err = json.Unmarshal(data, &result)
				return result, err
			} else if resp.StatusCode == 409 {
				return nil, fmt.Errorf("Conflict")
			}
			return nil, fmt.Errorf("Internal server error")
		}
		return nil, fmt.Errorf("Expecting response payload to be not null")
	}
	return nil, err
}

// UpdateOAuth2Client updates the scopes and redirect urls of a registered oauth client
func (client *HydraClient) updateOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/clients/", client.ClientID)
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                client.ClientID,
			ClientSecret:            client.ClientSecret,
			Scopes:                  strings.Join(client.Scopes, " "),
			TokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.grantTypes,
		})

	logrus.Debugf("UpdateOAuth2Client - PUT payload: '%v'", payloadData)
	resp, data, err := client.Admin.Put(p, payloadData)
	if err == nil {
		if resp != nil {
			if resp.StatusCode == 200 {
				err = json.Unmarshal(data, &result)
				return result, err
			}
			return nil, fmt.Errorf("Internal server error")
		}
		return nil, fmt.Errorf("Expecting response payload to be not null")
	}
	return nil, err
}

// Logout call hydra service and logs the user out
func (client *HydraClient) Logout(subject string) error {
	resp, _, err := client.Admin.Delete(fmt.Sprintf("/oauth2/auth/sessions/login?subject=%v", subject))

	if err == nil {
		if resp != nil {
			logrus.Debugf("Logout: %v - %v", subject, resp.StatusCode)
			if resp.StatusCode == 204 || resp.StatusCode == 201 {
				return nil
			} else if resp.StatusCode == 404 {
				return fmt.Errorf("Not found")
			}
			return fmt.Errorf("Internal server error")
		}
		return fmt.Errorf("Expecting response payload to be not null")
	}

	return err
}
