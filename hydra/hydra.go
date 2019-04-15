package hydra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/sirupsen/logrus"

	"github.com/labbsr0x/goh/gohclient"
)

// Client holds data and methods to communicate with an hydra service instance
type Client struct {
	AdminURL   *url.URL
	PublicURL  *url.URL
	HTTPClient *gohclient.Default
	Scopes     []string
}

// Init initializes a hydra client
func (client *Client) Init(hydraAdminURL, hydraPublicURL string, scopes []string) *Client {
	client.AdminURL, _ = url.Parse(hydraAdminURL)
	client.PublicURL, _ = url.Parse(hydraPublicURL)
	client.HTTPClient = gohclient.New("application/json", "application/json")
	client.Scopes = scopes

	logrus.Infof("Hydra enpoints - Admin: '%v' - Public: '%v'", client.AdminURL.String(), client.PublicURL.String())
	return client
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *Client) IntrospectToken(token string, scopes []string) (result HydraToken, err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/oauth2/introspect/")
	payloadData, _ := json.Marshal(IntrospectTokenRequestPayload{Token: token, Scope: strings.Join(scopes, " ")})

	logrus.Debugf("IntrospectToken - url: '%v' - payload: '%v'", u.String(), payloadData)
	resp, data, err := client.HTTPClient.Post(u.String(), payloadData)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// GetOAuth2Client calls hydra to get a clients information
func (client *Client) GetOAuth2Client(clientID string) (result *OAuth2Client, err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/clients/", clientID)

	logrus.Debugf("GetOAuth2Client - url: '%v'", u.String())
	resp, data, err := client.HTTPClient.Get(u.String())
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// CreateOAuth2Client calls hydra to create an oauth2 client
func (client *Client) CreateOAuth2Client(clientID, clientSecret string, scopes []string) (result *OAuth2Client, err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/clients")
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                clientID,
			ClientSecret:            clientSecret,
			TokenEndpointAuthMethod: "client_secret_post",
			Scopes:                  strings.Join(scopes, " "),
			GrantTypes:              []string{"client_credentials", "authorization_code", "refresh_token"}})

	logrus.Debugf("CreateOAuth2Client - url: '%v' - payload: '%v'", u.String(), payloadData)
	resp, data, err := client.HTTPClient.Post(u.String(), payloadData)
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

// DoClientCredentialsFlow calls hydra's oauth2/token and starts a client credentials flow
func (client *Client) DoClientCredentialsFlow(clientID, clientSecret string, scopes []string) (t *oauth2.Token, err error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &Transporter{
			FakeTLSTermination: true,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	})

	u, _ := url.Parse(client.PublicURL.String())
	u.Path = path.Join(u.Path, "/oauth2/token")
	oauthConfig := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     u.String(),
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	return oauthConfig.Token(ctx)
}
