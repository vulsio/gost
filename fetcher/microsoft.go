package fetcher

import (
	"encoding/json"
	"encoding/xml"
	"regexp"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	"github.com/pkg/errors"
	"github.com/tealeg/xlsx"
)

var (
	updateListURL                   = "https://api.msrc.microsoft.com/Updates?api-version=2016-08-01"
	bulletinSearchURL               = "https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"
	bulletinSearchFrom2001To2008URL = "https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch2001-2008.xlsx"
	msDateRegexp                    = regexp.MustCompile(`\d+[-\/]\d+[-\/]\d+`)
)

// RetrieveMicrosoftCveDetails :
// https://api.msrc.microsoft.com/cvrf/2017-Jan?api-version=2016-08-01
func RetrieveMicrosoftCveDetails(apikey string) (cves []models.MicrosoftXML, err error) {
	u, err := util.FetchURL(updateListURL, apikey)
	if err != nil {
		return nil, err
	}
	var updateList models.Updatelist
	if err = json.Unmarshal(u, &updateList); err != nil {
		return nil, err
	}

	for _, update := range updateList.Value {
		log15.Info("Fetching", "URL", update.CvrfURL)
		cveXML, err := util.FetchURL(update.CvrfURL, apikey)
		if err != nil {
			return nil,
				errors.Wrapf(err, "Failed to fetch cve data from Microsoft. targetURL: %s", update.CvrfURL)
		}

		var cve models.MicrosoftXML
		if err = xml.Unmarshal(cveXML, &cve); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}
	return cves, nil
}

// RetrieveMicrosoftBulletinSearch :
func RetrieveMicrosoftBulletinSearch() (cves []models.MicrosoftBulletinSearch, err error) {
	for _, bsURL := range []string{bulletinSearchURL, bulletinSearchFrom2001To2008URL} {
		bs, err := util.FetchURL(bsURL, "")
		if err != nil {
			return nil, err
		}
		bsCves, err := XlsToModel(bs)
		if err != nil {
			return nil, err
		}
		cves = append(cves, bsCves...)
	}
	return cves, nil
}

// XlsToModel :
func XlsToModel(bs []byte) (cves []models.MicrosoftBulletinSearch, err error) {
	xlFile, err := xlsx.OpenBinary(bs)
	if err != nil {
		return nil, err
	}
	for _, sheet := range xlFile.Sheets {
		for i, row := range sheet.Rows {
			// ignore header
			if i == 0 {
				continue
			}
			var cve models.MicrosoftBulletinSearch
			err := row.ReadStruct(&cve)
			if err != nil {
				return nil, err
			}
			cve.DatePosted = msDateRegexp.FindString(cve.DatePosted)
			if len(cve.BulletinKB) == 0 {
				continue
			}
			cves = append(cves, cve)
		}
	}
	return cves, nil
}
