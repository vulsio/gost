package cmd

import (
	"os"
	"path/filepath"

	"github.com/knqyf263/go-security-tracker/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch data of the security tracker",
	Long:  `Fetch data of the security tracker`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().String("log-dir", "", "/path/to/log")
	viper.BindPFlag("log-dir", fetchCmd.PersistentFlags().Lookup("log-dir"))
	viper.SetDefault("log-dir", util.GetDefaultLogDir())

	fetchCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	viper.BindPFlag("debug-sql", fetchCmd.PersistentFlags().Lookup("debug-sql"))
	viper.SetDefault("debug-sql", false)

	fetchCmd.PersistentFlags().String("dbpath", "", "/path/to/sqlite3 or SQL connection string")
	viper.BindPFlag("dbpath", fetchCmd.PersistentFlags().Lookup("dbpath"))
	pwd := os.Getenv("PWD")
	viper.SetDefault("dbpath", filepath.Join(pwd, "tracker.sqlite3"))

	fetchCmd.PersistentFlags().String("dbtype", "", "Database type to store data in (sqlite3, mysql or postgres supported)")
	viper.BindPFlag("dbtype", fetchCmd.PersistentFlags().Lookup("dbtype"))
	viper.SetDefault("dbtype", "sqlite3")

	fetchCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port (default: empty)")
	viper.BindPFlag("http-proxy", fetchCmd.PersistentFlags().Lookup("http-proxy"))
	viper.SetDefault("http-proxy", "")
}
