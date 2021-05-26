package cmd

import (
	"errors"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/knqyf263/gost/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
)

// redhatCmd represents the redhat command
var redHatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Fetch the CVE information from aquasecurity/vuln-list",
	Long:  `Fetch the CVE information from aquasecurity/vuln-list`,
	RunE:  fetchRedHat,
}

func init() {
	fetchCmd.AddCommand(redHatCmd)
}

func fetchRedHat(cmd *cobra.Command, args []string) (err error) {
	cves, err := fetcher.FetchRedHatVulnList()
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
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log15.Error("Failed to get FetchMeta from DB.", "err", err)
			return err
		}
	} else {
		if fetchMeta.OutDated() {
			log15.Error("Failed to Insert CVEs into DB. SchemaVersion is old", "SchemaVersion", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
			return xerrors.New("Failed to Insert CVEs into DB. SchemaVersion is old")
		}
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		log15.Error("Failed to upsert FetchMeta to DB.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
