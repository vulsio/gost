package cmd

import (
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	trivyDB "github.com/aquasecurity/trivy/pkg/db"
	trivyLog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

// redhatCmd represents the redhat command
var redHatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Fetch the CVE information from knqyf263/vuln-list",
	Long:  `Fetch the CVE information from knqyf263/vuln-list`,
	RunE:  fetchRedHat,
}

func init() {
	fetchCmd.AddCommand(redHatCmd)
}

func fetchRedHat(cmd *cobra.Command, args []string) (err error) {
	log15.Info("Initialize Database")

	//TODO debug option
	if err := trivyLog.InitLogger(true, false); err != nil {
		log15.Error("Fatal")
		return nil
	}

	if err = trivyDB.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	cves, err := fetcher.FetchRedHatVulnList()
	if err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	log15.Info("Insert RedHat into DB", "db", driver.Name())
	if err := driver.InsertRedhat(cves); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
