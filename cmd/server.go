package cmd

import (
	"github.com/knqyf263/go-security-tracker/db"
	"github.com/knqyf263/go-security-tracker/log"
	"github.com/knqyf263/go-security-tracker/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start security tracker HTTP server",
	Long:  `Start security tracker HTTP server`,
	RunE:  serverExecute,
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().String("bind", "", "HTTP server bind to IP address (default: loop back interface")
	viper.BindPFlag("bind", serverCmd.PersistentFlags().Lookup("bind"))
	viper.SetDefault("bind", "127.0.0.1")

	serverCmd.PersistentFlags().String("port", "", "HTTp server port number (default: 11235")
	viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port"))
	viper.SetDefault("port", "11235")
}

func serverExecute(cmd *cobra.Command, args []string) (err error) {
	logDir := viper.GetString("log-dir")
	log.Initialize(logDir)

	driver, err := db.InitDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		return err
	}

	log.Info("Starting HTTP Server...")
	if err = server.Start(logDir, driver); err != nil {
		log.Error(err)
		return err
	}

	return nil
}
