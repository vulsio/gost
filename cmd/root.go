package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/util"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log15.Error("Failed to execute command", "err", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gost.yaml)")

	RootCmd.PersistentFlags().String("log-dir", "", "/path/to/log")
	viper.BindPFlag("log-dir", RootCmd.PersistentFlags().Lookup("log-dir"))
	viper.SetDefault("log-dir", util.GetDefaultLogDir())

	RootCmd.PersistentFlags().Bool("debug", false, "debug mode (default: false)")
	viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))
	viper.SetDefault("debug", false)

	RootCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	viper.BindPFlag("debug-sql", RootCmd.PersistentFlags().Lookup("debug-sql"))
	viper.SetDefault("debug-sql", false)

	RootCmd.PersistentFlags().String("dbpath", "", "/path/to/sqlite3 or SQL connection string")
	viper.BindPFlag("dbpath", RootCmd.PersistentFlags().Lookup("dbpath"))
	pwd := os.Getenv("PWD")
	viper.SetDefault("dbpath", filepath.Join(pwd, "tracker.sqlite3"))

	RootCmd.PersistentFlags().String("dbtype", "", "Database type to store data in (sqlite3, mysql or postgres supported)")
	viper.BindPFlag("dbtype", RootCmd.PersistentFlags().Lookup("dbtype"))
	viper.SetDefault("dbtype", "sqlite3")

	RootCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port (default: empty)")
	viper.BindPFlag("http-proxy", RootCmd.PersistentFlags().Lookup("http-proxy"))
	viper.SetDefault("http-proxy", "")

	logDir := viper.GetString("log-dir")
	debug := viper.GetBool("debug")
	util.SetLogger(logDir, debug)
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
