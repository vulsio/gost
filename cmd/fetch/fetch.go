package fetch

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// FetchCmd represents the fetch command
var FetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of the security tracker",
	Long:  `Fetch the data of the security tracker`,
}

func init() {
	// subcommands
	FetchCmd.AddCommand(fetchRedHatCmd)
	FetchCmd.AddCommand(fetchRedHatAPICmd)
	FetchCmd.AddCommand(fetchDebianCmd)
	FetchCmd.AddCommand(fetchUbuntuCmd)
	FetchCmd.AddCommand(fetchMicrosoftCmd)

	// flags
	FetchCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	FetchCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "gost.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	FetchCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	FetchCmd.PersistentFlags().Int("batch-size", 15, "The number of batch size to insert.")
	FetchCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port")
}
