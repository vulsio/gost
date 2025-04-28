package fetcher

import (
	"compress/gzip"
	"encoding/json"
	"net/http"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

const (
	vulnerabilityURL = "https://raw.githubusercontent.com/vulsio/windows-vuln-feed/main/dist/vulnerability/vulnerability.json.gz"
	supercedenceURL  = "https://raw.githubusercontent.com/vulsio/windows-vuln-feed/main/dist/supercedence/supercedence.json.gz"
)

// RetrieveMicrosoftCveDetails :
func RetrieveMicrosoftCveDetails() ([]models.MicrosoftVulnerability, []models.MicrosoftSupercedence, error) {
	resp, err := util.FetchURL(vulnerabilityURL)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch Microsoft Vulnerability data. err: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, xerrors.Errorf("Failed to fetch Microsoft Vulnerability data. err: status code: %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	var vulns []models.MicrosoftVulnerability
	if err := json.NewDecoder(gz).Decode(&vulns); err != nil {
		return nil, nil, err
	}

	resp, err = util.FetchURL(supercedenceURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, xerrors.Errorf("Failed to fetch Microsoft Supercedence data. err: status code: %d", resp.StatusCode)
	}

	gz, err = gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	var supercedences []models.MicrosoftSupercedence
	if err := json.NewDecoder(gz).Decode(&supercedences); err != nil {
		return nil, nil, err
	}

	return vulns, supercedences, nil
}
