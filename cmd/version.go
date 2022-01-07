package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vulsio/gost/config"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Long:  `Show version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("gost %s %s\n", config.Version, config.Revision)
	},
}
