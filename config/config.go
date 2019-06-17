package config

import (
	"net/url"
	"strings"

	"github.com/labbsr0x/goh/gohtypes"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TokenKey defines the token key type as string
type TokenKey string

const (
	// WhisperTokenEnvKey defines the whisper token key
	WhisperTokenEnvKey TokenKey = "WHISPER_CLIENT_TOKEN"
)

const (
	whisperAdminURL  = "whisper-admin-url"
	whisperPublicURL = "whisper-public-url"
	clientID         = "client-id"
	clientSecret     = "client-secret"
	logLevel         = "log-level"
	scopes           = "scopes"
	redirectURIs     = "redirect-uris"
)

// Flags define the fields that will be passed via cmd
type Flags struct {
	WhisperAdminURL  *url.URL
	WhisperPublicURL *url.URL
	ClientID         string
	ClientSecret     string
	LogLevel         string
	Scopes           []string
	RedirectURIs     []string
}

// AddFlags adds flags for Builder.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(whisperAdminURL, "", "The Whisper Admin Endpoint for managing client apps.")
	flags.String(whisperPublicURL, "", "The Whisper Public Endpoint for firing up authorization flows.")
	flags.String(clientID, "", "The client ID for this app. If hydra doesn't recognize this ID, it will be created as is. If creation fails, execution of this utility panics.")
	flags.String(clientSecret, "", "[optional] The client secret for this app, in terms of oauth2 client credentials. Must be at least 6 characters long. If not set, client is considered public and should perform the authorization code flow with PKCE")
	flags.String(logLevel, "info", "[optional] The log level (trace, debug, info, warn, error, fatal, panic).")
	flags.String(scopes, "", "[optional] A comma separated list of scopes the client can ask for.")
	flags.String(redirectURIs, "", "[optional] A comma separated list of possible redirect_uris this client can talk to when performing an oauth2 authorization code flow.")
}

// InitFromViper initializes the flags from Viper.
func (flags *Flags) InitFromViper(v *viper.Viper) *Flags {
	var err error
	flags.ClientID = v.GetString(clientID)
	flags.ClientSecret = v.GetString(clientSecret)
	flags.LogLevel = v.GetString(logLevel)
	flags.Scopes = strings.Split(v.GetString(scopes), ",")
	flags.RedirectURIs = strings.Split(v.GetString(redirectURIs), ",")

	flags.WhisperAdminURL, err = url.Parse(v.GetString(whisperAdminURL))
	gohtypes.PanicIfError("Invalid whisper admin url", 500, err)
	flags.WhisperPublicURL, err = url.Parse(v.GetString(whisperPublicURL))
	gohtypes.PanicIfError("Invalid whisper public url", 500, err)

	flags.check()

	logLevel, err := logrus.ParseLevel(flags.LogLevel)
	if err != nil {
		logrus.Errorf("Not able to parse log level string. Setting default level: info.")
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	return flags
}

func (flags *Flags) check() {
	if flags.ClientID == "" || flags.WhisperAdminURL.Host == "" || flags.WhisperPublicURL.Host == "" {
		panic("client-id, whisper-admin-url and whisper-public-url cannot be empty")
	}

	if len(flags.ClientSecret) < 6 {
		panic("client-secret must be at least 6 characters long")
	}
}
