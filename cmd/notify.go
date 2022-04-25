package cmd

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/config"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/notifier"
	"github.com/vulsio/gost/util"
)

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Notify update about the specified CVE",
	Long:  `Notify update about the specified CVE`,
	RunE:  executeNotify,
}

func init() {
	RootCmd.AddCommand(notifyCmd)

	RootCmd.PersistentFlags().Bool("to-email", false, "Send notification via Email")
	_ = viper.BindPFlag("to-email", RootCmd.PersistentFlags().Lookup("to-email"))

	RootCmd.PersistentFlags().Bool("to-slack", false, "Send notification via Slack")
	_ = viper.BindPFlag("to-slack", RootCmd.PersistentFlags().Lookup("to-slack"))
}

func executeNotify(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	log15.Info("Load toml config")
	var conf config.Config
	if _, err = toml.DecodeFile("config.toml", &conf); err != nil {
		return err
	}
	return notifyRedhat(conf)
}

func notifyRedhat(conf config.Config) error {
	watchCveURL := []string{}
	for cveID := range conf.Redhat {
		watchCveURL = append(watchCveURL, fetcher.GetRedhatCveDetailURL(cveID))
	}

	log15.Info(fmt.Sprintf("Fetched %d CVEs", len(watchCveURL)))
	cveJSONs, err := fetcher.RetrieveRedhatCveDetails(watchCveURL)
	if err != nil {
		return err
	}

	cves, err := models.ConvertRedhat(cveJSONs)
	if err != nil {
		return nil

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
		return xerrors.Errorf("Failed to notify command. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	for _, cve := range cves {
		// Select CVE information from DB
		c, err := driver.GetRedhat(cve.Name)
		if err != nil {
			return err
		}
		notifier.ClearIDRedhat(c)

		cve.Cvss3.Cvss3BaseScore = "10 (This is dummy)"
		cve.ThreatSeverity = "High (This is dummy)"
		body := notifier.DiffRedhat(c, &cve, conf.Redhat[cve.Name])
		if body != "" {
			subject := fmt.Sprintf("%s Update %s", conf.EMail.SubjectPrefix, cve.Name)
			body = fmt.Sprintf("%s\nhttps://access.redhat.com/security/cve/%s\n========================================================\n",
				cve.Name, cve.Name) + body
			if err := notify(subject, body, conf); err != nil {
				return err
			}
		}
	}
	return nil
}

func notify(subject, body string, conf config.Config) (err error) {
	if viper.GetBool("to-email") {
		sender := notifier.NewEMailSender(conf.EMail)
		log15.Info("Send e-mail")
		if err = sender.Send(subject, body); err != nil {
			return xerrors.Errorf("Failed to send e-mail. err: %w", err)
		}
	}

	if viper.GetBool("to-slack") {
		log15.Info("Send slack")
		if err = notifier.SendSlack(body, conf.Slack); err != nil {
			return xerrors.Errorf("Failed to send to Slack. err: %w", err)
		}
	}
	return nil
}
