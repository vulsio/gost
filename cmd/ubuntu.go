package cmd

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// ubuntuCmd represents the ubuntu command
var ubuntuCmd = &cobra.Command{
	Use:   "ubuntu",
	Short: "Fetch the CVE information from aquasecurity/vuln-list",
	Long:  `Fetch the CVE information from aquasecurity/vuln-list`,
	RunE:  fetchUbuntu,
}

func init() {
	fetchCmd.AddCommand(ubuntuCmd)
}

func fetchUbuntu(cmd *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	cves, err := fetcher.FetchUbuntuVulnList()
	if err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
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

	log15.Info("Fetched", "CVEs", len(cves))
	log15.Info("Insert Ubuntu into DB", "db", driver.Name())
	if err := driver.InsertUbuntu(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
