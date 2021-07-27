package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ksamlauth",
	Short: "ksamlauth enables SAML2.0 authentication for kubernetes clusters",
	Long: `This is a multipart program, which allows users to use SAML2.0 to
authenticate against an identity provider and then perform
authenticated actions against a kubernetes cluster. For more
information view the help for "login" and "daemon".`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.UsageString())
	},
}

func init() {
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug messages")
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(validateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		return
	}
}
