package cmd

import (
	"errors"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	microsoftCmd.PersistentFlags().String("apikey", "", "microsoft apikey")
	viper.BindPFlag("apikey", microsoftCmd.PersistentFlags().Lookup("apikey"))
	viper.SetDefault("apikey", "")
}

func fetchMicrosoft(cmd *cobra.Command, args []string) (err error) {
	log15.Info("Initialize Database")
	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	log15.Info("Fetched all CVEs from Microsoft")
	apiKey := viper.GetString("apikey")
	if len(apiKey) == 0 {
		return errors.New("apikey is required")
	}
	cves, err := fetcher.RetrieveMicrosoftCveDetails(apiKey)
	if err != nil {
		return err
	}

	xls, err := fetcher.RetrieveMicrosoftBulletinSearch()
	if err != nil {
		return err
	}

	log15.Info("Insert Microsoft CVEs into DB", "db", driver.Name())
	if err := driver.InsertMicrosoft(cves, xls); err != nil {
		log15.Error("Failed to insert.", "dbpath",
			viper.GetString("dbpath"), "err", err)
		return err
	}
	return nil
}
