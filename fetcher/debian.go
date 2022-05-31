package fetcher

import (
	"encoding/json"

	"golang.org/x/xerrors"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// RetrieveDebianCveDetails returns CVE details from https://security-tracker.debian.org/tracker/data/json
func RetrieveDebianCveDetails() (cves models.DebianJSON, err error) {
	url := "https://security-tracker.debian.org/tracker/data/json"
	cveJSON, err := util.FetchURL(url)
	if err != nil {
		return cves, xerrors.Errorf("Failed to fetch cve data from Debian. err: %w", err)
	}

	// cveJSON, err := ioutil.ReadFile("./debian.json")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return cves, err
	// }

	if err := json.Unmarshal(cveJSON, &cves); err != nil {
		return nil, xerrors.Errorf("failed to decode Debian JSON: %w", err)
	}

	return cves, nil
}
