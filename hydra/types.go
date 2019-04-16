package hydra

import "net/http"

// Token holds a hydra token's data
type Token struct {
	Active            bool                   `json:"active"`
	Audiences         []string               `json:"aud,omitempty"`
	ClientID          string                 `json:"client_id"`
	Expiration        int64                  `json:"exp"`
	Extra             map[string]interface{} `json:"ext,omitempty"`
	IssuedAt          int64                  `json:"iat"`
	IssuerURL         string                 `json:"iss"`
	NotBefore         int64                  `json:"nbf"`
	ObfuscatedSubject string                 `json:"obfuscated_subject,omitempty"`
	Scope             string                 `json:"scope"`
	Subject           string                 `json:"sub"`
	TokenType         string                 `json:"token_type"`
	Username          string                 `json:"username"`
}

// AcceptLoginRequestPayload holds the data to communicate with hydra's accept login api
type AcceptLoginRequestPayload struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember"`
	RememberFor int    `json:"remember_for"`
	ACR         string `json:"acr"`
}

// AcceptConsentRequestPayload holds the data to communicate with hydra's accept consent api
type AcceptConsentRequestPayload struct {
	GrantScope               []string            `json:"grant_scope"`
	GrantAccessTokenAudience []string            `json:"grant_access_token_audience"`
	Remember                 bool                `json:"remember"`
	RememberFor              int                 `json:"remember_for"`
	Session                  TokenSessionPayload `json:"session"`
}

// TokenSessionPayload holds additional data to be carried with the created token
type TokenSessionPayload struct {
	IDToken     interface{} `json:"id_token"`
	AccessToken interface{} `json:"access_token"`
}

// RejectConsentRequestPayload holds the data to communicate with hydra's reject consent api
type RejectConsentRequestPayload struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OAuth2Client holds the data of an oauth2 hydra client
type OAuth2Client struct {
	AllowedCorsOrigins      []string `json:"allowed_cors_origins"`
	Audience                []string `json:"audience"`
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientURI               string   `json:"client_uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scopes                  string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	RedirectURIs            []string `json:"redirect_uris"`
}

// IntrospectTokenRequestPayload holds the data to communicate with hydra's introspect token api
type IntrospectTokenRequestPayload struct {
	Token string `json:"token"`
	Scope string `json:"scope"`
}

// Transporter to enable the definition of a FakeTLSTermination
type Transporter struct {
	*http.Transport
	FakeTLSTermination bool
}

// RoundTrip overwrites the parent transport round trip to enable/disable fake tls termination
func (t *Transporter) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.FakeTLSTermination {
		req.Header.Set("X-Forwarded-Proto", "https")
	}

	return t.Transport.RoundTrip(req)
}
