package fetcher

import (
	"bytes"
	"compress/gzip"
	"encoding/json"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	vulnerabilityURL = "https://raw.githubusercontent.com/vulsio/windows-vuln-feed/main/dist/vulnerability/vulnerability.json.gz"
	supercedenceURL  = "https://raw.githubusercontent.com/vulsio/windows-vuln-feed/main/dist/supercedence/supercedence.json.gz"
)

// RetrieveMicrosoftCveDetails :
func RetrieveMicrosoftCveDetails() ([]models.MicrosoftVulnerability, []models.MicrosoftSupercedence, error) {
	bs, err := util.FetchURL(vulnerabilityURL)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	var vulns []models.MicrosoftVulnerability
	if err := json.NewDecoder(gz).Decode(&vulns); err != nil {
		return nil, nil, err
	}

	bs, err = util.FetchURL(supercedenceURL)
	if err != nil {
		return nil, nil, err
	}
	gz, err = gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, nil, err
	}
	var supercedences []models.MicrosoftSupercedence
	if err := json.NewDecoder(gz).Decode(&supercedences); err != nil {
		return nil, nil, err
	}

	return vulns, supercedences, nil
}
