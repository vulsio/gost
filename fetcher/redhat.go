package fetcher

import (
	"encoding/json"
	"fmt"

	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
)

// ListAllRedhatCves returns the list of all CVEs from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#list_all_cves
func ListAllRedhatCves(after string) (entries []models.RedhatEntry, err error) {
	url := fmt.Sprintf("https://access.redhat.com/labs/securitydataapi/cve.json?after=%s&per_page=100000", after)
	body, err := util.FetchURL(url)
	if err != nil {
		return entries, fmt.Errorf("Failed to fetch RedHat CVEs list: %v, url: %s", err, url)
	}

	json.Unmarshal([]byte(body), &entries)
	return entries, nil
}

// GetRedhatCveDetailURL returns CVE detail URL.
func GetRedhatCveDetailURL(cveID string) (url string) {
	return fmt.Sprintf("https://access.redhat.com/labs/securitydataapi/cve/%s.json", cveID)

}

// RetrieveRedhatCveDetails returns full CVE details from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#retrieve_a_cve
func RetrieveRedhatCveDetails(urls []string) (cves []models.RedhatCVEJSON, err error) {
	cveJSONs, err := util.FetchConcurrently(urls, 10)
	if err != nil {
		return cves,
			fmt.Errorf("Failed to fetch cve data from RedHat. err: %s", err)
	}

	for _, cveJSON := range cveJSONs {
		var cve models.RedhatCVEJSON
		json.Unmarshal([]byte(cveJSON), &cve)
		cves = append(cves, cve)
	}

	return cves, nil
}
