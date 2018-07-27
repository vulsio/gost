package cmd

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/inconshreveable/log15"

	"github.com/knqyf263/gost/config"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/fetcher"
	"github.com/knqyf263/gost/notifier"
	"github.com/knqyf263/gost/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Notifiy update about the specified CVE",
	Long:  `Notifiy update about the specified CVE`,
	RunE:  executeNotify,
}

func init() {
	RootCmd.AddCommand(notifyCmd)

	RootCmd.PersistentFlags().Bool("to-email", false, "Send notification via Email")
	viper.BindPFlag("to-email", RootCmd.PersistentFlags().Lookup("to-email"))
	viper.SetDefault("to-email", false)

	RootCmd.PersistentFlags().Bool("to-slack", false, "Send notification via Slack")
	viper.BindPFlag("to-slack", RootCmd.PersistentFlags().Lookup("to-slack"))
	viper.SetDefault("to-slack", false)
}

func executeNotify(cmd *cobra.Command, args []string) (err error) {
	log15.Info("Load toml config")
	var conf config.Config
	if _, err = toml.DecodeFile("config.toml", &conf); err != nil {
		return err
	}
	notifyRedhat(conf)
	return err
}

func notifyRedhat(conf config.Config) error {
	var watchCveURL []string
	for cveID := range conf.Redhat {
		watchCveURL = append(watchCveURL, fetcher.GetRedhatCveDetailURL(cveID))
	}

	log15.Info(fmt.Sprintf("Fetched %d CVEs", len(watchCveURL)))
	cveJSONs, err := fetcher.RetrieveRedhatCveDetails(watchCveURL)
	if err != nil {
		return err
	}

	cves, err := db.ConvertRedhat(cveJSONs)
	if err != nil {
		return nil

	}

	log15.Info("Initialize Database")
	driver, locked, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	for _, cve := range cves {
		// Select CVE information from DB
		c := driver.GetRedhat(cve.Name)
		db.ClearIDRedhat(c)

		cve.Cvss3.Cvss3BaseScore = "10 (This is dummy)"
		cve.ThreatSeverity = "High (This is dummy)"
		body := util.DiffRedhat(c, &cve, conf.Redhat[cve.Name])
		if body != "" {
			subject := fmt.Sprintf("%s Update %s", conf.EMail.SubjectPrefix, cve.Name)
			body = fmt.Sprintf("%s\nhttps://access.redhat.com/security/cve/%s\n========================================================\n",
				cve.Name, cve.Name) + body
			notify(subject, body, conf)
		}
	}
	return nil
}

func notify(subject, body string, conf config.Config) (err error) {
	if viper.GetBool("to-email") {
		sender := notifier.NewEMailSender(conf.EMail)
		log15.Info("Send e-mail")
		if err = sender.Send(subject, body); err != nil {
			return fmt.Errorf("Failed to send e-mail. err: %s", err)
		}
	}

	if viper.GetBool("to-slack") {
		log15.Info("Send slack")
		if err = notifier.SendSlack(body, conf.Slack); err != nil {
			return fmt.Errorf("Failed to send to Slack. err: %s", err)
		}
	}
	return nil
}
