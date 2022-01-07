package cmd

import (
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/server"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start security tracker HTTP server",
	Long:  `Start security tracker HTTP server`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("debug-sql", cmd.PersistentFlags().Lookup("debug-sql")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbpath", cmd.PersistentFlags().Lookup("dbpath")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbtype", cmd.PersistentFlags().Lookup("dbtype")); err != nil {
			return err
		}

		if err := viper.BindPFlag("bind", cmd.PersistentFlags().Lookup("bind")); err != nil {
			return err
		}

		if err := viper.BindPFlag("port", cmd.PersistentFlags().Lookup("port")); err != nil {
			return err
		}

		return nil
	},
	RunE: executeServer,
}

func init() {
	serverCmd.PersistentFlags().Bool("debug-sql", false, "SQL debug mode")
	serverCmd.PersistentFlags().String("dbpath", filepath.Join(os.Getenv("PWD"), "gost.sqlite3"), "/path/to/sqlite3 or SQL connection string")
	serverCmd.PersistentFlags().String("dbtype", "sqlite3", "Database type to store data in (sqlite3, mysql, postgres or redis supported)")
	serverCmd.PersistentFlags().String("bind", "127.0.0.1", "HTTP server bind to IP address")
	serverCmd.PersistentFlags().String("port", "1325", "HTTP server port number")
}

func executeServer(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to start server. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	log15.Info("Starting HTTP Server...")
	if err = server.Start(viper.GetBool("log-to-file"), viper.GetString("log-dir"), driver); err != nil {
		return xerrors.Errorf("Failed to start server. err: %w", err)
	}

	return nil
}
