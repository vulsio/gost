package fetcher

import (
	"encoding/json"
	"net/http"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

const archAdvURL = "https://security.archlinux.org/json"

// FetchArch fetch Advisory JSONs
func FetchArch() ([]models.ArchADVJSON, error) {
	resp, err := util.FetchURL(archAdvURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch Security Advisory from Arch Linux. err: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("Failed to fetch Security Advisory from Arch Linux. err: status code: %d", resp.StatusCode)
	}

	var advs []models.ArchADVJSON
	if err := json.NewDecoder(resp.Body).Decode(&advs); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal Arch Linux Security Advisory JSON. err: %w", err)
	}

	return advs, nil
}
