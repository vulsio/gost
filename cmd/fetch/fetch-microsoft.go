package fetch

import (
	"errors"
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

// fetchMicrosoftCmd represents the microsoft command
var fetchMicrosoftCmd = &cobra.Command{
	Use:   "microsoft",
	Short: "Fetch the CVE information from Microsoft",
	Long:  `Fetch the CVE information from Microsoft`,
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

		if err := viper.BindPFlag("apikey", cmd.PersistentFlags().Lookup("apikey")); err != nil {
			return err
		}

		return nil
	},
	RunE: fetchMicrosoft,
}

func fetchMicrosoft(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
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

	log15.Info("Fetched all CVEs from Microsoft")
	apiKey := viper.GetString("apikey")
	if len(apiKey) == 0 {
		return errors.New("apikey is required")
	}
	cveXMLs, err := fetcher.RetrieveMicrosoftCveDetails(apiKey)
	if err != nil {
		return err
	}
	cveXls, err := fetcher.RetrieveMicrosoftBulletinSearch()
	if err != nil {
		return err
	}
	cves, product := models.ConvertMicrosoft(cveXMLs, cveXls)

	log15.Info("Insert Microsoft CVEs into DB", "db", driver.Name())
	if err := driver.InsertMicrosoft(cves, product); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
