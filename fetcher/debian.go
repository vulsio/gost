package fetcher

import (
	"encoding/json"
	"fmt"

	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
)

// https://security-tracker.debian.org/tracker/data/json
func RetrieveDebianCveDetails() (cves models.DebianJSON, err error) {
	url := "https://security-tracker.debian.org/tracker/data/json"
	cveJSON, err := util.FetchURL(url, "")
	if err != nil {
		return cves,
			fmt.Errorf("Failed to fetch cve data from Debian. err: %s", err)
	}

	// cveJSON, err := ioutil.ReadFile("./debian.json")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return cves, err
	// }

	json.Unmarshal(cveJSON, &cves)

	return cves, nil
}
