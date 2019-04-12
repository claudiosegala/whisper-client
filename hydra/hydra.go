package hydra

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/abilioesteves/goh/gohtypes"
	"github.com/sirupsen/logrus"

	"github.com/abilioesteves/goh/gohclient"
)

// Client holds data and methods to communicate with an hydra service instance
type Client struct {
	AdminURL   *url.URL
	HTTPClient *gohclient.Default
}

// Init initializes a hydra client
func (client *Client) Init(hydraAdminURL string) *Client {
	client.AdminURL, _ = url.Parse(hydraAdminURL)
	client.HTTPClient = gohclient.New("application/json", "application/json")

	logrus.Infof("Hydra enpoint url: %v", client.AdminURL.String())
	return client
}

// GetLoginRequestInfo retrieves information to drive decisions over how to deal with the login request
func (client *Client) GetLoginRequestInfo(challenge string) map[string]interface{} {
	return client.get("login", challenge)
}

// AcceptLoginRequest sends an accept login request to hydra
func (client *Client) AcceptLoginRequest(challenge string, payload AcceptLoginRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("login", challenge, "accept", data)
}

// GetConsentRequestInfo retrieves information to drive decisions over how to deal with the consent request
func (client *Client) GetConsentRequestInfo(challenge string) map[string]interface{} {
	return client.get("consent", challenge)
}

// AcceptConsentRequest sends an accept login request to hydra
func (client *Client) AcceptConsentRequest(challenge string, payload AcceptConsentRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("consent", challenge, "accept", data)
}

// RejectConsentRequest sends a reject login request to hydra
func (client *Client) RejectConsentRequest(challenge string, payload RejectConsentRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("consent", challenge, "reject", data)
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *Client) IntrospectToken(token string) (result HydraToken, err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/oauth2/introspect/")
	logrus.Debugf("url: '%v'", u.String())
	resp, data, err := client.HTTPClient.Get(u.String())
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// GetOAuth2Client calls hydra to get a clients information
func (client *Client) GetOAuth2Client(clientID string) (result *OAuth2Client, err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/clients/", clientID)
	logrus.Debugf("url: '%v'", u.String())
	resp, data, err := client.HTTPClient.Get(u.String())
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, result)
	}
	return result, err
}

// CreateClient calls hydra to create an oauth2 client
func (client *Client) CreateOAuth2Client(clientID, clientSecret string) (err error) {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/clients")
	logrus.Debugf("url: '%v'", u.String())
	payloadData, _ := json.Marshal(OAuth2Client{ClientID: clientID, ClientSecret: clientSecret})
	resp, _, err := client.HTTPClient.Post(u.String(), payloadData)
	if err == nil {
		if resp != nil {
			if resp.StatusCode == 201 {
				return nil
			} else if resp.StatusCode == 409 {
				return fmt.Errorf("Client already exists")
			} else {
				return fmt.Errorf("Internal server error")
			}
		}
		return fmt.Errorf("Expecting response payload to be not null")
	}
	return err
}

func (client *Client) get(flow, challenge string) map[string]interface{} {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/oauth2/auth/requests/", flow, url.QueryEscape(challenge))
	logrus.Debugf("url: '%v'", u.String())
	return client.treatResponse(client.HTTPClient.Get(u.String()))
}

func (client *Client) put(flow, challenge, action string, data []byte) map[string]interface{} {
	u, _ := url.Parse(client.AdminURL.String())
	u.Path = path.Join(u.Path, "/oauth2/auth/requests/", flow, url.QueryEscape(challenge), action)
	logrus.Debugf("url: '%v'", u.String())
	return client.treatResponse(client.HTTPClient.Put(u.String(), data))
}

func (client *Client) treatResponse(resp *http.Response, data []byte, err error) map[string]interface{} {
	if err == nil {
		if resp.StatusCode >= 200 && resp.StatusCode <= 302 {
			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err == nil {
				return result
			}
			panic(gohtypes.Error{Code: 500, Err: err, Message: "Error while decoding hydra's response bytes"})
		}
	}
	panic(gohtypes.Error{Code: 500, Err: err, Message: "Error while communicating with Hydra"})
}
