package cmd

import (
	"fmt"
	"github.com/labbsr0x/whisper-client/client"
	"github.com/labbsr0x/whisper-client/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// introspectCmd represents the introspect command
var introspectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect with whisper",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := new(config.Config).InitFromViper(viper.GetViper())
		whisperClient := new(client.WhisperClient).InitFromConfig(config)

		token, err := whisperClient.CheckCredentials()
		if err != nil {
			return err
		}

		tokenJSONString := whisperClient.GetTokenAsJSONStr(token)

		fmt.Printf(tokenJSONString)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)

	config.AddFlags(introspectCmd.Flags())

	err := viper.GetViper().BindPFlags(introspectCmd.Flags())
	if err != nil {
		panic(err)
	}
}

