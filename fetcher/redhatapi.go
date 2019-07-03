package fetcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
)

// ListAllRedhatCves returns the list of all CVEs from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#list_all_cves
func ListAllRedhatCves(before, after string, wait int) (entries []models.RedhatEntry, err error) {
	for page := 1; ; page++ {
		url := fmt.Sprintf("https://access.redhat.com/labs/securitydataapi/cve.json?page=%d&after=%s", page, after)
		if before != "" {
			url += fmt.Sprintf("&before=%s", before)

		}
		body, err := util.FetchURL(url, "")
		if err != nil {
			return entries, fmt.Errorf("Failed to fetch RedHat CVEs list: %v, url: %s", err, url)
		}

		entryList := []models.RedhatEntry{}
		if err = json.Unmarshal(body, &entryList); err != nil {
			return nil, err
		}
		if len(entryList) == 0 {
			break
		}
		entries = append(entries, entryList...)
		time.Sleep(time.Duration(wait) * time.Second)
	}
	return entries, nil
}

// GetRedhatCveDetailURL returns CVE detail URL.
func GetRedhatCveDetailURL(cveID string) (url string) {
	return fmt.Sprintf("https://access.redhat.com/labs/securitydataapi/cve/%s.json", cveID)

}

// RetrieveRedhatCveDetails returns full CVE details from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#retrieve_a_cve
func RetrieveRedhatCveDetails(urls []string) (cves []models.RedhatCVEJSON, err error) {
	cveJSONs, err := util.FetchConcurrently(urls, viper.GetInt("threads"), viper.GetInt("wait"))
	if err != nil {
		return cves, fmt.Errorf("Failed to fetch cve data from RedHat. err: %s", err)
	}

	for _, cveJSON := range cveJSONs {
		var cve models.RedhatCVEJSON
		if err = json.Unmarshal(cveJSON, &cve); err != nil {
			return nil, err
		}
		switch cve.TempAffectedRelease.(type) {
		case []interface{}:
			var ar models.RedhatCVEJSONAffectedReleaseArray
			if err = json.Unmarshal(cveJSON, &ar); err != nil {
				return nil, fmt.Errorf("Unknown affected_release type err: %s", err)
			}
			cve.AffectedRelease = ar.AffectedRelease
		case map[string]interface{}:
			var ar models.RedhatCVEJSONAffectedReleaseObject
			if err = json.Unmarshal(cveJSON, &ar); err != nil {
				return nil, fmt.Errorf("Unknown affected_release type err: %s", err)
			}
			cve.AffectedRelease = []models.RedhatAffectedRelease{ar.AffectedRelease}
		case nil:
		default:
			return nil, errors.New("Unknown affected_release type")
		}

		switch cve.TempPackageState.(type) {
		case []interface{}:
			var ps models.RedhatCVEJSONPackageStateArray
			if err = json.Unmarshal(cveJSON, &ps); err != nil {
				return nil, fmt.Errorf("Unknown package_state type err: %s", err)
			}
			cve.PackageState = ps.PackageState
		case map[string]interface{}:
			var ps models.RedhatCVEJSONPackageStateObject
			if err = json.Unmarshal(cveJSON, &ps); err != nil {
				return nil, fmt.Errorf("Unknown package_state type err: %s", err)
			}
			cve.PackageState = []models.RedhatPackageState{ps.PackageState}
		case nil:
		default:
			return nil, errors.New("Unknown package_state type")
		}
		cves = append(cves, cve)
	}

	return cves, nil
}
