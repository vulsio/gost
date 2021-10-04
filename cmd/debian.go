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

// debianCmd represents the debian command
var debianCmd = &cobra.Command{
	Use:   "debian",
	Short: "Fetch the CVE information from Debian",
	Long:  `Fetch the CVE information from Debian`,
	RunE:  fetchDebian,
}

func init() {
	fetchCmd.AddCommand(debianCmd)
}

func fetchDebian(cmd *cobra.Command, args []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return err
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	log15.Info("Fetched all CVEs from Debian")
	cveJSONs, err := fetcher.RetrieveDebianCveDetails()
	if err != nil {
		return err
	}
	cves := models.ConvertDebian(cveJSONs)

	log15.Info("Fetched", "CVEs", len(cves))

	log15.Info("Insert Debian CVEs into DB", "db", driver.Name())
	if err := driver.InsertDebian(cves); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
