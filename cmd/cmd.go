package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/abilioesteves/whisper-client/client"

	"github.com/abilioesteves/whisper-client/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "whisper-client",
	Short: "An utility for performing an oauth2 client-credentials flow with Hydra to be used with Whisper",
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := new(config.Flags).InitFromViper(viper.GetViper())
		whisperClient := new(client.WhisperClient).InitFromFlags(flags)
		return whisperClient.CheckCredentials()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	config.AddFlags(rootCmd.Flags())

	if err := viper.GetViper().BindPFlags(rootCmd.Flags()); err != nil {
		panic(err)
	}
}

func initConfig() {
	viper.SetEnvPrefix(os.Getenv("CLIENT_ENV_PREFIX")) // all
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv() // read in environment variables that match
}
