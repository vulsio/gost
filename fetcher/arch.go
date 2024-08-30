package fetcher

import (
	"encoding/json"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

const archAdvURL = "https://security.archlinux.org/json"

// FetchArch fetch Advisory JSONs
func FetchArch() ([]models.ArchADVJSON, error) {
	bs, err := util.FetchURL(archAdvURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch Security Advisory from Arch Linux. err: %w", err)
	}

	var advs []models.ArchADVJSON
	if err := json.Unmarshal(bs, &advs); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal Arch Linux Security Advisory JSON. err: %w", err)
	}

	return advs, nil
}
