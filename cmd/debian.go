package cmd

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
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

	log15.Info("Fetched all CVEs from Debian")
	cves, err := fetcher.RetrieveDebianCveDetails()
	if err != nil {
		return err
	}

	log15.Info("Fetched", "CVEs", len(cves))

	log15.Info("Insert Debian CVEs into DB", "db", driver.Name())
	if err := driver.InsertDebian(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath",
			viper.GetString("dbpath"), "err", err)
		return err
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "err", err)
		return err
	}

	return nil
}
