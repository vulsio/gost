package cmd

import (
	"github.com/spf13/cobra"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of the security tracker",
	Long:  `Fetch the data of the security tracker`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)
}
