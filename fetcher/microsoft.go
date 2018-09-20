package fetcher

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
)

var (
	updateListURL = "https://api.msrc.microsoft.com/Updates?api-version=2016-08-01"
)

// RetrieveMicrosoftCveDetails :
// https://api.msrc.microsoft.com/cvrf/2017-Jan?api-version=2016-08-01
func RetrieveMicrosoftCveDetails(apikey string) (cves []models.MicrosoftXML, err error) {
	u, err := util.FetchURL(updateListURL, apikey)
	if err != nil {
		return nil, err
	}
	var updateList models.Updatelist
	if err = json.Unmarshal([]byte(u), &updateList); err != nil {
		return nil, err
	}

	for _, update := range updateList.Value {
		log15.Info("Fetching", "URL", update.CvrfURL)
		cveXML, err := util.FetchURL(update.CvrfURL, apikey)
		if err != nil {
			return nil,
				fmt.Errorf("Failed to fetch cve data from Microsoft. targetURL: %s, err: %s", update.CvrfURL, err)
		}

		var cve models.MicrosoftXML
		if err = xml.Unmarshal([]byte(cveXML), &cve); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}
	return cves, nil
}
