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
			if i == 0 {
				continue
			}
			var cve models.MicrosoftBulletinSearch
			for j, cell := range row.Cells {
				text := cell.String()
				switch j {
				case 0:
					// 01-31-01 or [$-110009]11/11/2008
					cve.DatePosted = msDateRegexp.FindString(text)
				case 1:
					cve.BulletinID = text
				case 2:
					cve.BulletinKB = text
				case 3:
					cve.Severity = text
				case 4:
					cve.Impact = text
				case 5:
					cve.Title = text
				case 6:
					cve.AffectedProduct = text
				case 7:
					cve.ComponentKB = text
				case 8:
					cve.AffectedComponent = text
				case 9:
				case 10:
				case 11:
					cve.Supersedes = text
				case 12:
					cve.Reboot = text
				case 13:
					cve.CVEs = text
				default:
					log15.Info("NewData", "Index", j, "Content", text)
				}
			}
			if len(cve.BulletinKB) == 0 {
				continue
			}
			cves = append(cves, cve)
		}
	}
	return cves, nil
}
