package fetch

import (
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// fetchRedhatCmd represents the redhat command
var fetchRedHatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Fetch the CVE information from aquasecurity/vuln-list",
	Long:  `Fetch the CVE information from aquasecurity/vuln-list`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("debug-sql", cmd.Parent().PersistentFlags().Lookup("debug-sql")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbpath", cmd.Parent().PersistentFlags().Lookup("dbpath")); err != nil {
			return err
		}

		if err := viper.BindPFlag("dbtype", cmd.Parent().PersistentFlags().Lookup("dbtype")); err != nil {
			return err
		}

		if err := viper.BindPFlag("batch-size", cmd.Parent().PersistentFlags().Lookup("batch-size")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: fetchRedHat,
}

func fetchRedHat(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	cveJSONs, err := fetcher.FetchRedHatVulnList()
	if err != nil {
		return xerrors.Errorf("Failed to initialize vulnerability DB. err: %w", err)
	}
	cves, err := models.ConvertRedhat(cveJSONs)
	if err != nil {
		return xerrors.Errorf("Failed to convert RedhatCVE. err: %w", err)
	}

	log15.Info("Initialize Database")
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
		return xerrors.Errorf("Failed to Insert CVEs into DB. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
