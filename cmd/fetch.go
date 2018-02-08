package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of the security tracker",
	Long:  `Fetch the data of the security tracker`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().Int("wait", 0, "Interval between fetch (seconds)")
	viper.BindPFlag("wait", fetchCmd.PersistentFlags().Lookup("wait"))
	viper.SetDefault("wait", 0)

	fetchCmd.PersistentFlags().Int("threads", 5, "The number of threads to be used")
	viper.BindPFlag("threads", fetchCmd.PersistentFlags().Lookup("threads"))
	viper.SetDefault("threads", 5)
}
