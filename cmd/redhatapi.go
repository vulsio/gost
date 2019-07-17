package cmd

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	redHatAPICmd.PersistentFlags().String("after", "", "Fetch CVEs after the specified date (e.g. 2017-01-01) (default: 1970-01-01)")
	viper.BindPFlag("after", redHatAPICmd.PersistentFlags().Lookup("after"))
	viper.SetDefault("after", "1970-01-01")

	redHatAPICmd.PersistentFlags().String("before", "", "Fetch CVEs before the specified date (e.g. 2017-01-01)")
	viper.BindPFlag("before", redHatAPICmd.PersistentFlags().Lookup("before"))
	viper.SetDefault("before", "")

	redHatAPICmd.PersistentFlags().Bool("list-only", false, "")
	viper.BindPFlag("list-only", redHatAPICmd.PersistentFlags().Lookup("list-only"))
	viper.SetDefault("list-only", false)
}

func fetchRedHatAPI(cmd *cobra.Command, args []string) (err error) {
	log15.Info("Initialize Database")
	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	log15.Info("Fetch the list of CVEs")
	entries, err := fetcher.ListAllRedhatCves(
		viper.GetString("before"), viper.GetString("after"), viper.GetInt("threads"))
	if err != nil {
		log15.Error("Failed to fetch the list of CVEs.", "err", err)
		return err
	}
	var resourceURLs []string
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
	cves, err := fetcher.RetrieveRedhatCveDetails(resourceURLs)
	if err != nil {
		log15.Error("Failed to fetch the CVE details.", "err", err)
		return err
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
