/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/nikogura/jwt-ssh-agent-go/pkg/agentjwt/client"
	"github.com/spf13/cobra"
	"log"
	"os/user"
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Make a signed JWT.",
	Long: `
Make a signed JWT.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if username == "" {
			u, err := user.Current()
			if err != nil {
				log.Fatalf("failed to find current user: %s", err)
			}

			username = u.Username
		}

		if pubKeyFile == "~/.ssh/id_ed25519.pub" {
			hd, err := homedir.Dir()
			if err != nil {
				log.Fatalf("error determinint user homedir: %s", err)
			}

			pubKeyFile = fmt.Sprintf("%s/.ssh/id_ed25519.pub", hd)
		}

		cfg := &client.ClientConfig{
			Username:   username,
			PubKeyFile: pubKeyFile,
			Timeout:    timeoutSeconds,
		}

		client, err := client.NewClient(cfg)
		if err != nil {
			log.Fatalf("failed creating client: %s", err)
		}

		token, err := client.MakeToken(server)
		if err != nil {
			log.Fatalf("failed creating JWT: %s", err)
		}

		fmt.Printf("%s", token)

	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)

}
