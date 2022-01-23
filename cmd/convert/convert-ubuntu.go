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

var convertUbuntuCmd = &cobra.Command{
	Use:   "ubuntu",
	Short: "Convert the CVE information from Ubuntu",
	Long:  `Convert the CVE information from Ubuntu`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlag("vuln-dir", cmd.Parent().PersistentFlags().Lookup("vuln-dir")); err != nil {
			return err
		}

		if err := viper.BindPFlag("http-proxy", cmd.Parent().PersistentFlags().Lookup("http-proxy")); err != nil {
			return err
		}

		return nil
	},
	RunE: convertUbuntu,
}

// https://github.com/vulsio/goval-dictionary/blob/master/config/config.go
var ubuVerCodename = map[string]string{
	"trusty":  "14.04",
	"xenial":  "16.04",
	"bionic":  "18.04",
	"eoan":    "19.10",
	"focal":   "20.04",
	"groovy":  "20.10",
	"hirsute": "21.04",
	"impish":  "21.10",
}

func convertUbuntu(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	vulnDir := filepath.Join(viper.GetString("vuln-dir"), "ubuntu")
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

	log15.Info("Fetching Ubuntu CVEs")
	cveJSONs, err := fetcher.FetchUbuntuVulnList()
	if err != nil {
		return xerrors.Errorf("Failed to initialize vulnerability DB. err: %w", err)
	}
	cves := models.ConvertUbuntu(cveJSONs)

	log15.Info("Converting Ubuntu CVEs")
	cvesMap := map[string][]models.UbuntuCVE{}
	for _, cve := range cves {
		verPatchesMap := map[string][]models.UbuntuPatch{}
		for _, patch := range cve.Patches {
			for _, relPatch := range patch.ReleasePatches {
				ver, ok := ubuVerCodename[relPatch.ReleaseName]
				if !ok {
					continue
				}
				verPatchesMap[ver] = append(verPatchesMap[ver], models.UbuntuPatch{PackageName: patch.PackageName, ReleasePatches: []models.UbuntuReleasePatch{relPatch}})
			}
		}

		for ver, patches := range verPatchesMap {
			cvesMap[ver] = append(cvesMap[ver], models.UbuntuCVE{
				PublicDateAtUSN:   cve.PublicDateAtUSN,
				CRD:               cve.CRD,
				Candidate:         cve.Candidate,
				PublicDate:        cve.PublicDate,
				References:        cve.References,
				Description:       cve.Description,
				UbuntuDescription: cve.UbuntuDescription,
				Notes:             cve.Notes,
				Bugs:              cve.Bugs,
				Priority:          cve.Priority,
				DiscoveredBy:      cve.DiscoveredBy,
				AssignedTo:        cve.AssignedTo,
				Patches:           patches,
				Upstreams:         cve.Upstreams,
			})
		}
	}

	log15.Info("Deleting Old Ubuntu CVEs")
	dirs, err := filepath.Glob(filepath.Join(vulnDir, "*"))
	if err != nil {
		return xerrors.Errorf("Failed to get all dirs in vuln directory. err: %w", err)
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return xerrors.Errorf("Failed to remove vuln data file. err: %w", err)
		}
	}

	log15.Info("Creating Ubuntu CVEs")
	for majorVer, cves := range cvesMap {
		if err := os.MkdirAll(filepath.Join(vulnDir, majorVer), 0700); err != nil {
			return xerrors.Errorf("Failed to create vuln directory. err: %w", err)
		}

		for _, cve := range cves {
			f, err := os.Create(filepath.Join(vulnDir, majorVer, fmt.Sprintf("%s.json", cve.Candidate)))
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
	if err := setLastUpdatedDate("gost/ubuntu"); err != nil {
		return xerrors.Errorf("Failed to set last updated date. err: %w", err)
	}

	return nil
}
