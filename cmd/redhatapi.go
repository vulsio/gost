package cmd

import (
	"fmt"
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

// redHatAPICmd represents the redhatAPI command
var redHatAPICmd = &cobra.Command{
	Use:   "redhatapi",
	Short: "Fetch the CVE information from Red Hat API",
	Long:  `Fetch the CVE information from Red Hat API`,
	RunE:  fetchRedHatAPI,
}

func init() {
	fetchCmd.AddCommand(redHatAPICmd)

	redHatAPICmd.PersistentFlags().String("after", "1970-01-01", "Fetch CVEs after the specified date (e.g. 2017-01-01)")
	_ = viper.BindPFlag("after", redHatAPICmd.PersistentFlags().Lookup("after"))

	redHatAPICmd.PersistentFlags().String("before", "", "Fetch CVEs before the specified date (e.g. 2017-01-01)")
	_ = viper.BindPFlag("before", redHatAPICmd.PersistentFlags().Lookup("before"))

	redHatAPICmd.PersistentFlags().Bool("list-only", false, "")
	_ = viper.BindPFlag("list-only", redHatAPICmd.PersistentFlags().Lookup("list-only"))
}

func fetchRedHatAPI(cmd *cobra.Command, args []string) (err error) {
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

	log15.Info("Fetch the list of CVEs")
	entries, err := fetcher.ListAllRedhatCves(
		viper.GetString("before"), viper.GetString("after"), viper.GetInt("threads"))
	if err != nil {
		return xerrors.Errorf("Failed to fetch the list of CVEs. err: %w", err)
	}
	resourceURLs := []string{}
	for _, entry := range entries {
		resourceURLs = append(resourceURLs, entry.ResourceURL)
	}

	if viper.GetBool("list-only") {
		for _, e := range entries {
			fmt.Printf("%s\t%s\n", e.CveID, e.PublicDate)
		}
		return nil
	}

	log15.Info(fmt.Sprintf("Fetched %d CVEs", len(entries)))
	cveJSONs, err := fetcher.RetrieveRedhatCveDetails(resourceURLs)
	if err != nil {
		return xerrors.Errorf("Failed to fetch the CVE details. err: %w", err)
	}
	cves, err := models.ConvertRedhat(cveJSONs)
	if err != nil {
		return xerrors.Errorf("Failed to convert RedhatCVE. err: %w", err)
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedDate = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
