package client

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"

	"github.com/labbsr0x/goh/gohtypes"
)

// GetLoginRequestInfo retrieves information to drive decisions over how to deal with the login request
func (client *hydraClient) GetLoginRequestInfo(challenge string) map[string]interface{} {
	return client.get("login", challenge)
}

// AcceptLoginRequest sends an accept login request to hydra
func (client *hydraClient) AcceptLoginRequest(challenge string, payload AcceptLoginRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("login", challenge, "accept", data)
}

// GetConsentRequestInfo retrieves information to drive decisions over how to deal with the consent request
func (client *hydraClient) GetConsentRequestInfo(challenge string) map[string]interface{} {
	return client.get("consent", challenge)
}

// AcceptConsentRequest sends an accept login request to hydra
func (client *hydraClient) AcceptConsentRequest(challenge string, payload AcceptConsentRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("consent", challenge, "accept", data)
}

// RejectConsentRequest sends a reject login request to hydra
func (client *hydraClient) RejectConsentRequest(challenge string, payload RejectConsentRequestPayload) map[string]interface{} {
	data, _ := json.Marshal(&payload)
	return client.put("consent", challenge, "reject", data)
}

func (client *hydraClient) get(flow, challenge string) map[string]interface{} {
	p := path.Join(client.admin.BaseURL.Path, "/oauth2/auth/requests/", flow) + "?challenge=" + url.QueryEscape(challenge)
	return client.treatResponse(client.admin.Get(p))
}

func (client *hydraClient) put(flow, challenge, action string, data []byte) map[string]interface{} {
	p := path.Join(client.admin.BaseURL.Path, "/oauth2/auth/requests/", flow, action) + "?challenge=" + url.QueryEscape(challenge)
	return client.treatResponse(client.admin.Put(p, data))
}

func (client *hydraClient) treatResponse(resp *http.Response, data []byte, err error) map[string]interface{} {
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
