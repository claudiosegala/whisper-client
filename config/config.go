package config

import (
	"strings"

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
	hydraAdminURL  = "hydra-admin-url"
	hydraPublicURL = "hydra-public-url"
	clientID       = "client-id"
	clientSecret   = "client-secret"
	logLevel       = "log-level"
	scopes         = "scopes"
)

// Flags define the fields that will be passed via cmd
type Flags struct {
	HydraAdminURL  string
	HydraPublicURL string
	ClientID       string
	ClientSecret   string
	LogLevel       string
	Scopes         []string
}

// AddFlags adds flags for Builder.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(hydraAdminURL, "", "The Hydra Admin Endpoint")
	flags.String(hydraPublicURL, "", "The Hydra Public Endpoint")
	flags.String(clientID, "", "The client ID for this app. If hydra doesn't recognize this ID, it will be created as is. If creation fails, execution of this utility panics.")
	flags.String(clientSecret, "", "The client secret for this app, in terms of oauth2 client credentials. Must be at least 6 characters long")
	flags.String(logLevel, "info", "The log level (trace, debug, info, warn, error, fatal, panic)")
	flags.String(scopes, "", "A comma separated list of scopes the client can ask for")
}

// InitFromViper initializes the flags from Viper.
func (flags *Flags) InitFromViper(v *viper.Viper) *Flags {
	flags.ClientID = v.GetString(clientID)
	flags.ClientSecret = v.GetString(clientSecret)
	flags.HydraAdminURL = v.GetString(hydraAdminURL)
	flags.HydraPublicURL = v.GetString(hydraPublicURL)
	flags.LogLevel = v.GetString(logLevel)
	flags.Scopes = strings.Split(v.GetString(scopes), ",")

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
	if flags.ClientID == "" || flags.ClientSecret == "" || flags.HydraAdminURL == "" || flags.HydraPublicURL == "" {
		panic("client-id, client-secret, hydra-admin-url and hydra-public-url cannot be empty")
	}

	if len(flags.ClientSecret) < 6 {
		panic("client-secret must be at least 6 characters long")
	}
}
