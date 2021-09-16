package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/util"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:           "gost",
	Short:         "Security Tracker",
	Long:          `Security Tracker`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gost.yaml)")

	RootCmd.PersistentFlags().Bool("log-to-file", false, "output log to file")
	_ = viper.BindPFlag("log-to-file", RootCmd.PersistentFlags().Lookup("log-to-file"))

	RootCmd.PersistentFlags().String("log-dir", util.GetDefaultLogDir(), "/path/to/log")
	_ = viper.BindPFlag("log-dir", RootCmd.PersistentFlags().Lookup("log-dir"))

	RootCmd.PersistentFlags().Bool("log-json", false, "output log as JSON")
	_ = viper.BindPFlag("log-json", RootCmd.PersistentFlags().Lookup("log-json"))

	RootCmd.PersistentFlags().Bool("debug", false, "debug mode")
	_ = viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))

	RootCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	_ = viper.BindPFlag("debug-sql", RootCmd.PersistentFlags().Lookup("debug-sql"))

	pwd := os.Getenv("PWD")
	RootCmd.PersistentFlags().String("dbpath", filepath.Join(pwd, "gost.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	_ = viper.BindPFlag("dbpath", RootCmd.PersistentFlags().Lookup("dbpath"))

	RootCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	_ = viper.BindPFlag("dbtype", RootCmd.PersistentFlags().Lookup("dbtype"))

	RootCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port (default: empty)")
	_ = viper.BindPFlag("http-proxy", RootCmd.PersistentFlags().Lookup("http-proxy"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			log15.Error("Failed to find home directory.", "err", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".gost" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".gost")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
