package client

import (
	"context"

	"golang.org/x/oauth2"
)

// OAuthHelper holds the info and methods to help integrate with oauth
type OAuthHelper struct {
	codeVerifier string
	client       *WhisperClient
	oauth2Client *oauth2.Config
}

// Init initializes the oauth helper from a whisper client
func (oauthh *OAuthHelper) Init(client *WhisperClient, redirectURL string, scopes []string) *OAuthHelper {
	oauthh.client = client
	oauthh.oauth2Client = oauthh.getXOAuth2Client(redirectURL, scopes)

	return oauthh
}

// GetLoginURL builds the login url to authenticate with whisper
func (oauthh *OAuthHelper) GetLoginURL(redirectURL string, scopes []string) (url string, err error) {
	state, nonce, err := getStateAndNonce()
	if err == nil {
		codeVerifier, codeChallenge, err := getCodeVerifierAndChallenge()
		oauthh.codeVerifier = codeVerifier

		if err == nil {
			return oauthh.oauth2Client.AuthCodeURL(string(state), oauth2.SetAuthURLParam("nonce", string(nonce)), oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
		}
	}

	return "", err
}

// ExchangeCodeForToken performs the code exchange for an oauth token
func (oauthh *OAuthHelper) ExchangeCodeForToken(code, state string) (token *oauth2.Token, err error) {
	return oauthh.oauth2Client.Exchange(context.WithValue(context.Background(), oauth2.HTTPClient, getNoSSLClient()), code, oauth2.SetAuthURLParam("state", string(state)), oauth2.SetAuthURLParam("code_verifier", string(oauthh.codeVerifier)))
}

// getXOAuth2Client gets an oauth2 client to fire authorization flows
func (oauthh *OAuthHelper) getXOAuth2Client(redirectURL string, scopes []string) *oauth2.Config {
	authURL, _ := oauthh.client.public.BaseURL.Parse("/oauth2/auth")
	tokenURL, _ := oauthh.client.public.BaseURL.Parse("/oauth2/token")

	return &oauth2.Config{
		ClientID:     oauthh.client.clientID,
		ClientSecret: oauthh.client.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}
