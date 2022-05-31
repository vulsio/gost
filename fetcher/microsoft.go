package fetcher

import (
	"encoding/json"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	vulnerabilityURL = "http://0.0.0.0:8000/vulnerability/vulnerability.json"
	supercedenceURL  = "http://0.0.0.0:8000/supercedence/supercedence.json"
)

// RetrieveMicrosoftCveDetails :
func RetrieveMicrosoftCveDetails() ([]models.MicrosoftVulnerability, []models.MicrosoftSupercedence, error) {
	bs, err := util.FetchURL(vulnerabilityURL)
	if err != nil {
		return nil, nil, err
	}
	var vulns []models.MicrosoftVulnerability
	if err := json.Unmarshal(bs, &vulns); err != nil {
		return nil, nil, err
	}

	bs, err = util.FetchURL(supercedenceURL)
	if err != nil {
		return nil, nil, err
	}
	var supercedences []models.MicrosoftSupercedence
	if err := json.Unmarshal(bs, &supercedences); err != nil {
		return nil, nil, err
	}

	return vulns, supercedences, nil
}
