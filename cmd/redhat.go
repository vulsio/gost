package cmd

import (
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/knqyf263/gost/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// redhatCmd represents the redhat command
var redhatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Fetch the CVE information from Red Hat API",
	Long:  `Fetch the CVE information from Red Hat API`,
	RunE:  fetchRedhat,
}

func init() {
	fetchCmd.AddCommand(redhatCmd)

	redhatCmd.PersistentFlags().String("after", "", "Fetch CVEs after the specified date (e.g. 2017-01-01) (default: 1970-01-01)")
	viper.BindPFlag("after", redhatCmd.PersistentFlags().Lookup("after"))
	viper.SetDefault("after", "1970-01-01")

	redhatCmd.PersistentFlags().String("before", "", "Fetch CVEs before the specified date (e.g. 2017-01-01)")
	viper.BindPFlag("before", redhatCmd.PersistentFlags().Lookup("before"))
	viper.SetDefault("before", "")
}

func fetchRedhat(cmd *cobra.Command, args []string) (err error) {
	log.Infof("Fetch the list of CVEs")
	entries, err := fetcher.ListAllRedhatCves(
		viper.GetString("before"), viper.GetString("after"))
	var resourceURLs []string
	for _, entry := range entries {
		resourceURLs = append(resourceURLs, entry.ResourceURL)
	}

	log.Infof("Fetched %d CVEs", len(entries))
	cves, err := fetcher.RetrieveRedhatCveDetails(resourceURLs)
	if err != nil {
		return err
	}

	driver, err := db.InitDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		return err
	}

	log.Infof("Insert RedHat into DB (%s)", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		log.Errorf("Failed to insert. dbpath: %s, err: %s",
			viper.GetString("dbpath"), err)
		return err
	}

	return nil
}
