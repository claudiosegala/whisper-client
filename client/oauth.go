package client

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

// OAuthHelper holds the info and methods to help integrate with oauth
type OAuthHelper struct {
	codeVerifier string
	oauthURL     *url.URL
	clientID     string
	clientSecret string
	oauth2Client *oauth2.Config
	state        string
}

// Init initializes the oauth helper from a whisper client
func (oauthh *OAuthHelper) Init(oauthURL, redirectURL *url.URL, clientID, clientSecret string, scopes []string) *OAuthHelper {
	oauthh.oauthURL = oauthURL
	oauthh.clientID = clientID
	oauthh.clientSecret = clientSecret
	oauthh.oauth2Client = oauthh.getXOAuth2Client(redirectURL.String(), scopes)

	return oauthh
}

// GetLoginURL builds the login url to authenticate with whisper
func (oauthh *OAuthHelper) GetLoginURL() (string, error) {
	state, nonce, err := getStateAndNonce()
	if err == nil {
		codeVerifier, codeChallenge, err := getCodeVerifierAndChallenge()
		oauthh.codeVerifier = codeVerifier
		oauthh.state = state

		if err == nil {
			return oauthh.oauth2Client.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
		}
	}

	return "", err
}

// ExchangeCodeForToken performs the code exchange for an oauth token
func (oauthh *OAuthHelper) ExchangeCodeForToken(code string) (token *oauth2.Token, err error) {
	return oauthh.oauth2Client.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, getNoSSLClient()), code, oauth2.SetAuthURLParam("state", oauthh.state), oauth2.SetAuthURLParam("code_verifier", string(oauthh.codeVerifier)))
}

// getXOAuth2Client gets an oauth2 client to fire authorization flows
func (oauthh *OAuthHelper) getXOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
	authURL, _ := oauthh.oauthURL.Parse("/oauth2/auth")
	tokenURL, _ := oauthh.oauthURL.Parse("/oauth2/token")

	return &oauth2.Config{
		ClientID:     oauthh.clientID,
		ClientSecret: oauthh.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}
