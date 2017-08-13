package cmd

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/knqyf263/go-security-tracker/config"
	"github.com/knqyf263/go-security-tracker/db"
	"github.com/knqyf263/go-security-tracker/fetcher"
	"github.com/knqyf263/go-security-tracker/log"
	"github.com/knqyf263/go-security-tracker/models"
	"github.com/knqyf263/go-security-tracker/notifier"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Notifiy update abount the specified CVE",
	Long:  `Notifiy update abount the specified CVE`,
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
	log.Info("Load toml config")
	var config config.Config
	_, err = toml.DecodeFile("config.toml", &config)
	if err != nil {
		return err
	}

	log.Info("Fetched the list of CVEs from RedHat")
	entries, err := fetcher.ListAllRedhatCves()
	var watchCveURL []string
	for cveID := range config.Redhat {
		for _, e := range entries {
			if e.CveID == cveID {
				watchCveURL = append(watchCveURL, e.ResourceURL)
			}
		}
	}

	// watchCveURL := []string{
	// 	"https://access.redhat.com/labs/securitydataapi/cve/CVE-2012-1961.json",
	// 	// "https://access.redhat.com/labs/securitydataapi/cve/CVE-2014-7970.json",
	// }
	log.Infof("Fetched %d CVEs", len(watchCveURL))
	cveJSONs, err := fetcher.RetrieveRedhatCveDetails(watchCveURL)
	if err != nil {
		return err
	}

	cves := db.ConvertRedhat(cveJSONs)
	if err != nil {
		return nil

	}

	log.Info("Initialize Database")
	driver, err := db.InitDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		return err
	}

	for _, cve := range cves {
		c := driver.GetRedhat(cve.Name)
		db.ClearIDRedhat(c)
		cve.ThreatSeverity = "High"
		// cve.Mitigation = "Yabai"
		cve.Bugzilla.Description = "New Description"
		cve.Cvss.CvssBaseScore = "5.2"
		// cve.AffectedRelease[0].Package = "hoge"

		var body string
		body = diffRedhat(c, &cve, config.Redhat[cve.Name])
		if body != "" {
			body = fmt.Sprintf("%s\nhttps://access.redhat.com/security/cve/%s\n========================================================\n",
				cve.Name, cve.Name) + body
			fmt.Println(body)
			if viper.GetBool("to-email") {
				sender := notifier.NewEMailSender(config.EMail)
				subject := fmt.Sprintf("%s Update %s", config.EMail.SubjectPrefix, cve.Name)
				log.Info("Send e-mail")
				sender.Send(subject, body)
			}

			if viper.GetBool("to-slack") {
				log.Info("Send slack")
				notifier.SendSlack(body, config.Slack)
			}
		}
	}

	return nil

}

func diffRedhat(old, new *models.RedhatCVE, config config.WatchCve) (body string) {
	if config.ThreatSeverity {
		if old.ThreatSeverity != new.ThreatSeverity {
			body += fmt.Sprintf("\nThreat Secirity\n------------------\n[old]\n%v\n\n[new]\n%v\n",
				old.ThreatSeverity, new.ThreatSeverity)
		}
	}

	if config.Statement {
		if old.Statement != new.Statement {
			body += fmt.Sprintf("\nStatement\n------------------\n[old]\n%v\n[new]\n\n%v\n\n",
				old.Statement, new.Statement)
		}
	}

	if config.Acknowledgement {
		if old.Acknowledgement != new.Acknowledgement {
			body += fmt.Sprintf("\nAcknowledgement\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				old.Acknowledgement, new.Acknowledgement)
		}
	}

	if config.Mitigation {
		if old.Mitigation != new.Mitigation {
			body += fmt.Sprintf("\nMitigation\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				old.Mitigation, new.Mitigation)
			return
		}
	}

	if config.Bugzilla {
		if reflect.DeepEqual(old.Bugzilla, new.Bugzilla) == false {
			body += fmt.Sprintf(`
Bugzilla
------------------
[old]
BugzillaID: %s
Descriptiion: %s
URL: %s

[new]
BugzillaID: %s
Descriptiion: %s
URL: %s
`,
				old.Bugzilla.BugzillaID, old.Bugzilla.Description, old.Bugzilla.URL,
				new.Bugzilla.BugzillaID, new.Bugzilla.Description, new.Bugzilla.URL)
		}
	}

	if config.Cvss {
		if reflect.DeepEqual(old.Cvss, new.Cvss) == false {
			body += fmt.Sprintf(`
CVSS
------------------
[old]
Base Score: %s
Vector: %s
Status: %s

[new]
Base Score: %s
Vector: %s
Status: %s
`,
				old.Cvss.CvssBaseScore, old.Cvss.CvssScoringVector, old.Cvss.Status,
				new.Cvss.CvssBaseScore, new.Cvss.CvssScoringVector, new.Cvss.Status)
		}
	}

	if config.Cvss3 {
		if reflect.DeepEqual(old.Cvss3, new.Cvss3) == false {
			body += fmt.Sprintf(`
CVSSv3
------------------
[old]
Base Score: %s
Vector: %s
Status: %s

[new]
Base Score: %s
Vector: %s
Status: %s
`,
				old.Cvss3.Cvss3BaseScore, old.Cvss3.Cvss3ScoringVector, old.Cvss3.Status,
				new.Cvss3.Cvss3BaseScore, new.Cvss3.Cvss3ScoringVector, new.Cvss3.Status)
		}
	}

	if config.AffectedRelease && (len(old.AffectedRelease) > 0 || len(new.AffectedRelease) > 0) {
		oldAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, old := range old.AffectedRelease {
			oldAffectedRelease[old.ProductName+"#"+old.Package] = old
		}

		newAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, new := range new.AffectedRelease {
			newAffectedRelease[new.ProductName+"#"+new.Package] = new
		}

		for key, new := range newAffectedRelease {
			isNew := false

			old, ok := oldAffectedRelease[key]
			if ok {
				if reflect.DeepEqual(old, new) == false {
					isNew = true
				}
			} else {
				isNew = true
			}

			if !isNew {
				continue
			}

			body += fmt.Sprintf(`
Affected Release
------------------
[old]
Product Name: %s
Advisory: %s
Package: %s
CPE: %s
Release Date: %s

[new]
Product Name: %s
Advisory: %s
Package: %s
CPE: %s
Release Date: %s
`,
				old.ProductName, old.Advisory, old.Package, old.Cpe, old.ReleaseDate,
				new.ProductName, new.Advisory, new.Package, new.Cpe, new.ReleaseDate)
		}
	}

	if config.PackageState && (len(old.PackageState) > 0 || len(new.PackageState) > 0) {
		oldPackageState := map[string]models.RedhatPackageState{}
		for _, old := range old.PackageState {
			oldPackageState[old.ProductName+"#"+old.PackageName] = old
		}

		newPackageState := map[string]models.RedhatPackageState{}
		for _, new := range new.PackageState {
			newPackageState[new.ProductName+"#"+new.PackageName] = new
		}

		for key, new := range newPackageState {
			isNew := false

			old, ok := oldPackageState[key]
			if ok {
				if reflect.DeepEqual(old, new) == false {
					isNew = true
				}
			} else {
				isNew = true
			}

			if !isNew {
				continue
			}

			body += fmt.Sprintf(`
Package State
------------------
[old]
Product Name: %s
Fix State: %s
Package Name: %s

[new]
Product Name: %s
Fix State: %s
Package Name: %s
`,
				old.ProductName, old.FixState, old.PackageName,
				new.ProductName, new.FixState, new.PackageName)
		}

	}

	if config.Reference && (len(old.References) > 0 || len(new.References) > 0) {
		if reflect.DeepEqual(old.References, new.References) == false {
			o := []string{}
			for _, old := range old.References {
				o = append(o, old.Reference)
			}

			n := []string{}
			for _, new := range new.References {
				n = append(o, new.Reference)
			}
			body += fmt.Sprintf(`
Reference
------------------
[old]
%s

[new]
%s
`,
				strings.Join(o, "\n"), strings.Join(n, "\n"))
			return
		}
	}

	if config.Details && (len(old.Details) > 0 || len(new.Details) > 0) {
		if reflect.DeepEqual(old.Details, new.Details) == false {
			o := []string{}
			for _, old := range old.Details {
				o = append(o, old.Detail)
			}

			n := []string{}
			for _, new := range new.Details {
				n = append(n, new.Detail)
			}

			body += fmt.Sprintf(`
Detail
------------------
[old]
%s

[new]
%s
`,
				strings.Join(o, "\n"), strings.Join(n, "\n"))
			return
		}
	}

	return body

}
