/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/nikogura/jwt-ssh-agent-go/pkg/agentjwt/client"
	"io"
	"log"
	"os/user"

	"github.com/spf13/cobra"
)

// sendCmd represents the send command.
//
//nolint:gochecknoglobals // Cobra boilerplate
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Make a signed JWT and send it to a remote server",
	Long: `
Make a signed JWT, and send it to a remote server.
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

		resp, err := client.Send(server, token)
		if err != nil {
			log.Fatalf("failed sending request to %s: %s", server, err)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed reading response body: %s", err)
		}

		fmt.Printf("%s\n", body)
	},
}

//nolint:gochecknoinits // Cobra boilerplate
func init() {
	rootCmd.AddCommand(sendCmd)
}
