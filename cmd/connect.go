package cmd

import (
	"fmt"
	"github.com/labbsr0x/whisper-client/client"
	"github.com/labbsr0x/whisper-client/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
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
	rootCmd.AddCommand(connectCmd)

	config.AddFlags(connectCmd.Flags())

	err := viper.GetViper().BindPFlags(connectCmd.Flags())
	if err != nil {
		panic(err)
	}
}
