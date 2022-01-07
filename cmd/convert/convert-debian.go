package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/fetcher"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

var convertDebianCmd = &cobra.Command{
	Use:   "debian",
	Short: "Convert the CVE information from Debian",
	Long:  `Convert the CVE information from Debian`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: convertDebian,
}

var debVerCodename = map[string]string{
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
}

func convertDebian(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := filepath.Join(viper.GetString("vuln-dir"), "debian")
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

	log15.Info("Fetching Debian CVEs")
	cveJSONs, err := fetcher.RetrieveDebianCveDetails()
	if err != nil {
		return err
	}
	cves := models.ConvertDebian(cveJSONs)

	log15.Info("Converting Debian CVEs")
	cvesMap := map[string][]models.DebianCVE{}
	for _, cve := range cves {
		verPackagesMap := map[string][]models.DebianPackage{}
		for _, pack := range cve.Package {
			for _, rel := range pack.Release {
				majorVer, ok := debVerCodename[rel.ProductName]
				if !ok {
					continue
				}
				verPackagesMap[majorVer] = append(verPackagesMap[majorVer], models.DebianPackage{PackageName: pack.PackageName, Release: []models.DebianRelease{rel}})
			}
		}

		for majorVer, packs := range verPackagesMap {
			cvesMap[majorVer] = append(cvesMap[majorVer], models.DebianCVE{
				CveID:       cve.CveID,
				Scope:       cve.Scope,
				Description: cve.Description,
				Package:     packs,
			})
		}
	}

	log15.Info("Deleting Old Debian CVEs")
	dirs, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all dirs in vuln directory. err: %w", err)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating Debian CVEs")
	for majorVer, cves := range cvesMap {
		if err := os.MkdirAll(filepath.Join(vulnDir, majorVer), 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}

		for _, cve := range cves {
			f, err := os.Create(filepath.Join(vulnDir, majorVer, fmt.Sprintf("%s.json", cve.CveID)))
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
	if err := setLastUpdatedDate("gost/debian"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}
