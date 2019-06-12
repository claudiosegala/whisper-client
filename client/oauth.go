package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/labbsr0x/goh/gohclient"
	"github.com/labbsr0x/goh/gohtypes"
	"github.com/ory/x/randx"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// GetLoginURL builds the login url to authenticate with whisper
func (client *WhisperClient) GetLoginURL(redirectURL string, scopes []string) (url string, err error) {
	state, nonce, err := getStateAndNonce()
	if err == nil {
		oauth := client.getXOAuth2Client(redirectURL, scopes)

		return oauth.AuthCodeURL(string(state), oauth2.SetAuthURLParam("nonce", string(nonce))), nil
	}

	return "", err
}

// GetPKCELoginURL builds the login url to authenticate with whisper with pcke, i.e., no need for client-secret. The code verififer is returned to be stored and used in the exchange code for token step.
// For more details, please refer to the RCF7636 (https://tools.ietf.org/html/rfc7636)
func (client *WhisperClient) GetPKCELoginURL(redirectURL string, scopes []string) (url, codeVerifier string, err error) {
	state, nonce, err := getStateAndNonce()

	if err == nil {
		oauth := client.getXOAuth2Client(redirectURL, scopes)
		codeVerifier, err := randx.RuneSequence(48, randx.AlphaLower)
		gohtypes.PanicIfError("Unable to mount a random code_challenge 24 character string", 500, err)

		hash := sha256.New()
		hash.Write([]byte(string(codeVerifier)))
		codeChallenge := base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{}))

		return oauth.AuthCodeURL(string(state), oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), string(codeVerifier), nil
	}

	return "", "", err
}

// IntrospectToken calls hydra to introspect a access or refresh token
func (client *WhisperClient) IntrospectToken(token string) (result Token, err error) {
	httpClient, err := gohclient.New(nil, client.admin.BaseURL.String())
	httpClient.ContentType = "application/x-www-form-urlencoded"
	httpClient.Accept = "application/json"

	payload := url.Values{"token": []string{token}, "scopes": client.scopes}
	payloadData := bytes.NewBufferString(payload.Encode()).Bytes()
	logrus.Debugf("IntrospectToken - POST payload: '%v'", payloadData)

	resp, data, err := httpClient.Post("/oauth2/introspect/", payloadData)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		err = json.Unmarshal(data, &result)
	}
	return result, err
}

// DoClientCredentialsFlow calls hydra's oauth2/token and starts a client credentials flow
func (client *WhisperClient) DoClientCredentialsFlow() (t *oauth2.Token, err error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &Transporter{
			FakeTLSTermination: true,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	})

	u, _ := client.public.BaseURL.Parse("/oauth2/token")
	oauthConfig := clientcredentials.Config{
		ClientID:     client.clientID,
		ClientSecret: client.clientSecret,
		TokenURL:     u.String(),
		Scopes:       client.scopes,
		AuthStyle:    oauth2.AuthStyleInParams,
	}

	return oauthConfig.Token(ctx)
}

// Logout call hydra service and logs the user out
func (client *hydraClient) Logout(subject string) error {
	resp, _, err := client.admin.Delete(fmt.Sprintf("/oauth2/auth/sessions/login?subject=%v", subject))

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

// getXOAuth2Client gets an oauth2 client to fire authorization flows
func (client *WhisperClient) getXOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
	authURL, _ := client.public.BaseURL.Parse("/oauth2/auth")
	tokenURL, _ := client.public.BaseURL.Parse("/oauth2/token")

	return &oauth2.Config{
		ClientID:     client.clientID,
		ClientSecret: client.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}
