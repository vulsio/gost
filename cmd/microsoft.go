package cmd

import (
	"errors"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
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
}

func fetchMicrosoft(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	log15.Info("Initialize Database")
	driver, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if errors.Is(err, db.ErrDBLocked) {
			return xerrors.Errorf("Failed to open DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	log15.Info("Fetched all CVEs from Microsoft")
	vulns, supercedences, err := fetcher.RetrieveMicrosoftCveDetails()
	if err != nil {
		return err
	}
	cves, relations := models.ConvertMicrosoft(vulns, supercedences)

	log15.Info("Insert Microsoft CVEs into DB", "db", driver.Name())
	if err := driver.InsertMicrosoft(cves, relations); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
