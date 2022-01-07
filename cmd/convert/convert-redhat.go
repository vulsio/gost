package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

var convertRedHatCmd = &cobra.Command{
	Use:   "redhat",
	Short: "Convert the CVE information from RedHat",
	Long:  `Convert the CVE information from RedHat`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: convertRedHat,
}

func convertRedHat(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := filepath.Join(viper.GetString("vuln-dir"), "redhat")
	if f, err := os.Stat(vulnDir); err != nil {
		if !os.IsNotExist(err) {
			return xerrors.Errorf("Failed to check vuln directory. err: %w", err)
		}
		if err := os.MkdirAll(vulnDir, 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}
	} else if !f.IsDir() {
		return xerrors.Errorf("Failed to check vuln directory. err: %s is not directory", vulnDir)
	}

	log15.Info("Fetching RedHat CVEs")
	cveJSONs, err := fetcher.FetchRedHatVulnList()
	if err != nil {
		return xerrors.Errorf("Failed to initialize vulnerability DB. err: %w", err)
	}
	cves, err := models.ConvertRedhat(cveJSONs)
	if err != nil {
		return xerrors.Errorf("Failed to convert RedhatCVE. err: %w", err)
	}

	log15.Info("Converting RedHat CVEs")
	cvesMap := map[string][]models.RedhatCVE{}
	for _, cve := range cves {
		verPackagesMap := map[string][]models.RedhatPackageState{}
		for _, pack := range cve.PackageState {
			majorVer := strings.TrimPrefix(pack.Cpe, "cpe:/o:redhat:enterprise_linux:")
			if ver, err := strconv.Atoi(majorVer); err != nil || ver < 5 {
				continue
			}
			verPackagesMap[majorVer] = append(verPackagesMap[majorVer], pack)
		}

		for majorVer, packs := range verPackagesMap {
			cvesMap[majorVer] = append(cvesMap[majorVer], models.RedhatCVE{
				ThreatSeverity:       cve.ThreatSeverity,
				PublicDate:           cve.PublicDate,
				Bugzilla:             cve.Bugzilla,
				Cvss:                 cve.Cvss,
				Cvss3:                cve.Cvss3,
				Iava:                 cve.Iava,
				Cwe:                  cve.Cwe,
				Statement:            cve.Statement,
				Acknowledgement:      cve.Acknowledgement,
				Mitigation:           cve.Mitigation,
				AffectedRelease:      cve.AffectedRelease,
				PackageState:         packs,
				Name:                 cve.Name,
				DocumentDistribution: cve.DocumentDistribution,
				Details:              cve.Details,
				References:           cve.References,
			})
		}
	}

	log15.Info("Deleting Old RedHat CVEs")
	dirs, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all dirs in vuln directory. err: %w", err)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating RedHat CVEs")
	for majorVer, cves := range cvesMap {
		if err := os.MkdirAll(filepath.Join(vulnDir, majorVer), 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}

		for _, cve := range cves {
			f, err := os.Create(filepath.Join(vulnDir, majorVer, fmt.Sprintf("%s.json", cve.Name)))
			if err != nil {
				return xerrors.Errorf("Failed to create vuln data file. err: %w", err)
			}

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(cve); err != nil {
				_ = f.Close() // ignore error; Write error takes precedence
				return xerrors.Errorf("Failed to encode vuln data. err: %w", err)
			}

			if err := f.Close(); err != nil {
				return xerrors.Errorf("Failed to close vuln data file. err: %w", err)
			}
		}
	}

	log15.Info("Setting Last Updated Date")
	if err := setLastUpdatedDate("gost/redhat"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}
