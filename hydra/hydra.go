package hydra

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/sirupsen/logrus"

	"github.com/labbsr0x/goh/gohclient"
)

// Client holds data and methods to communicate with an hydra service instance
type Client struct {
	Public       *gohclient.Default
	Admin        *gohclient.Default
	Scopes       []string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
}

// Init initializes a hydra client
func (client *Client) Init(hydraAdminURL, hydraPublicURL, clientID, clientSecret string, scopes, redirectURIs []string) *Client {
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
	return client
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *Client) IntrospectToken(token string) (result Token, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/oauth2/introspect/")
	payloadData, _ := json.Marshal(IntrospectTokenRequestPayload{Token: token, Scope: strings.Join(client.Scopes, " ")})

	logrus.Debugf("IntrospectToken - POST payload: '%v'", payloadData)
	resp, data, err := client.Admin.Post(p, payloadData)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// GetOAuth2Client calls hydra to get a clients information
func (client *Client) GetOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/clients/", client.ClientID)

	logrus.Debugf("GetOAuth2Client - GET '%v'", client.ClientID)
	resp, data, err := client.Admin.Get(p)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// CreateOAuth2Client calls hydra to create an oauth2 client
func (client *Client) CreateOAuth2Client() (result *OAuth2Client, err error) {
	p := path.Join(client.Admin.BaseURL.Path, "/clients")
	payloadData, _ := json.Marshal(
		OAuth2Client{
			ClientID:                client.ClientID,
			ClientSecret:            client.ClientSecret,
			TokenEndpointAuthMethod: "client_secret_post",
			Scopes:                  strings.Join(client.Scopes, " "),
			GrantTypes:              []string{"client_credentials", "authorization_code", "refresh_token"},
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

// DoClientCredentialsFlow calls hydra's oauth2/token and starts a client credentials flow
func (client *Client) DoClientCredentialsFlow() (t *oauth2.Token, err error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &Transporter{
			FakeTLSTermination: true,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	})

	u, _ := client.Public.BaseURL.Parse("/oauth2/token")
	oauthConfig := clientcredentials.Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		TokenURL:     u.String(),
		Scopes:       client.Scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	return oauthConfig.Token(ctx)
}
