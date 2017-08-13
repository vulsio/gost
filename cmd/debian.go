package cmd

import (
	"github.com/knqyf263/go-security-tracker/db"
	"github.com/knqyf263/go-security-tracker/fetcher"
	"github.com/knqyf263/go-security-tracker/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// debianCmd represents the debian command
var debianCmd = &cobra.Command{
	Use:   "debian",
	Short: "Fetch the CVE information from Red Hat API",
	Long:  `Fetch the CVE information from Red Hat API`,
	RunE:  fetchDebian,
}

func init() {
	fetchCmd.AddCommand(debianCmd)
}

func fetchDebian(cmd *cobra.Command, args []string) (err error) {
	log.Infof("Fetched all CVEs from Debian")
	cves, err := fetcher.RetrieveDebianCveDetails()

	log.Infof("Initialize Database")
	driver, err := db.InitDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		return err
	}

	log.Infof("Insert Debian into DB (%s).", driver.Name())
	if err := driver.InsertDebian(cves); err != nil {
		log.Errorf("Failed to inert. dbpath: %s, err: %s",
			viper.GetString("dbpath"), err)
		return err
	}

	return nil
}
