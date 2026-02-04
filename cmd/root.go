/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals // Cobra boilerplate
var pubKeyFile string

//nolint:gochecknoglobals // Cobra boilerplate
var username string

//nolint:gochecknoglobals // Cobra boilerplate
var timeoutSeconds int

//nolint:gochecknoglobals // Cobra boilerplate
var server string

// rootCmd represents the base command when called without any subcommands.
//
//nolint:gochecknoglobals // Cobra boilerplate
var rootCmd = &cobra.Command{
	Use:   "jwt-ssh-agent-go",
	Short: "Example Client",
	Long: `
Example Client.

Useful for generating tokens for testing.

`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

//nolint:gochecknoinits // Cobra boilerplate
func init() {
	rootCmd.PersistentFlags().StringVarP(&pubKeyFile, "pubkey-file", "f", "~/.ssh/id_ed25519.pub", "File containing SSH public key to use for authentication.")
	rootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "Username for authentication")
	rootCmd.PersistentFlags().IntVarP(&timeoutSeconds, "timeout-seconds", "t", 10, "Timeout")
	rootCmd.PersistentFlags().StringVarP(&server, "server", "s", "http://127.0.0.1", "Server URL")
}
