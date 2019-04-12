package config

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	hydraAdminURL = "hydra-admin-url"
	clientID      = "client-id"
	clientSecret  = "client-secret"
)

// Flags define the fields that will be passed via cmd
type Flags struct {
	HydraAdminURL string
	ClientID      string
	ClientSecret  string
}

// AddFlags adds flags for Builder.
func AddFlags(flags *pflag.FlagSet) {
	flags.String(hydraAdminURL, "", "The Hydra Admin Endpoint")
	flags.String(clientID, "", "The client ID for this app. If hydra doesn't recognize this ID, it will be created as is. If creation fails, execution of this utility panics.")
	flags.String(clientSecret, "", "The client secret for this app, in terms of oauth2 client credentials")
}

// InitFromViper initializes the flags from Viper.
func (flags *Flags) InitFromViper(v *viper.Viper) *Flags {
	flags.ClientID = v.GetString(clientID)
	flags.ClientSecret = v.GetString(clientSecret)
	flags.HydraAdminURL = v.GetString(hydraAdminURL)

	flags.check()

	return flags
}

func (flags *Flags) check() {
	if flags.ClientID == "" || flags.ClientSecret == "" || flags.HydraAdminURL == "" {
		panic("client-id, client-secret and hydra-admin-url cannot be empty")
	}
}
