package cmd

import (
	"errors"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// microsoftCmd represents the microsoft command
var microsoftCmd = &cobra.Command{
	Use:   "microsoft",
	Short: "Fetch the CVE information from Microsoft",
	Long:  `Fetch the CVE information from Microsoft`,
	RunE:  fetchMicrosoft,
}

func init() {
	fetchCmd.AddCommand(microsoftCmd)

	microsoftCmd.PersistentFlags().String("apikey", "", "microsoft apikey")
	_ = viper.BindPFlag("apikey", microsoftCmd.PersistentFlags().Lookup("apikey"))
}

func fetchMicrosoft(cmd *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	log15.Info("Initialize Database")
	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		log15.Error("Failed to get FetchMeta from DB.", "err", err)
		return err
	}
	if fetchMeta.OutDated() {
		log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
		return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
	}

	log15.Info("Fetched all CVEs from Microsoft")
	apiKey := viper.GetString("apikey")
	if len(apiKey) == 0 {
		return errors.New("apikey is required")
	}
	cves, err := fetcher.RetrieveMicrosoftCveDetails(apiKey)
	if err != nil {
		return err
	}

	xls, err := fetcher.RetrieveMicrosoftBulletinSearch()
	if err != nil {
		return err
	}

	log15.Info("Insert Microsoft CVEs into DB", "db", driver.Name())
	if err := driver.InsertMicrosoft(cves, xls); err != nil {
		log15.Error("Failed to insert.", "dbpath",
			viper.GetString("dbpath"), "err", err)
		return err
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
