package hydra

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"

	"github.com/abilioesteves/goh/gohtypes"
	"github.com/sirupsen/logrus"
)

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
