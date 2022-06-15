package fetcher

import (
	"compress/gzip"
	"encoding/json"
	"os"

	"github.com/vulsio/gost/models"
)

// Until the data source is published, the path to the data source is received as an args
// const (
// 	vulnerabilityURL = "http://0.0.0.0:8000/vulnerability/vulnerability.json.gz"
// 	supercedenceURL  = "http://0.0.0.0:8000/supercedence/supercedence.json.gz"
// )

// RetrieveMicrosoftCveDetails :
func RetrieveMicrosoftCveDetails(vulnerabilityPath, supercedencePath string) ([]models.MicrosoftVulnerability, []models.MicrosoftSupercedence, error) {
	// bs, err := util.FetchURL(vulnerabilityURL)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// gz, err := gzip.NewReader(bytes.NewReader(bs))
	// if err != nil {
	// 	return nil, nil, err
	// }
	f, err := os.Open(vulnerabilityPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	var vulns []models.MicrosoftVulnerability
	if err := json.NewDecoder(gz).Decode(&vulns); err != nil {
		return nil, nil, err
	}

	// bs, err = util.FetchURL(supercedenceURL)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// gz, err = gzip.NewReader(bytes.NewReader(bs))
	// if err != nil {
	// 	return nil, nil, err
	// }
	f, err = os.Open(supercedencePath)
	if err != nil {
		return nil, nil, err
	}
	gz, err = gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	var supercedences []models.MicrosoftSupercedence
	if err := json.NewDecoder(gz).Decode(&supercedences); err != nil {
		return nil, nil, err
	}

	return vulns, supercedences, nil
}
