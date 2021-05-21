package cmd

import (
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

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
	cves, err := fetcher.FetchUbuntuVulnList()
	if err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dppath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertUbuntu(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
