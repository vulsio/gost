package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/git"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	ubuntuRepoURL = "https://github.com/aquasecurity/vuln-list-reserve.git"
	ubuntuDir     = "ubuntu"
)

// FetchUbuntuVulnList clones vuln-list and returns CVE JSONs
func FetchUbuntuVulnList() (entries []models.UbuntuCVEJSON, err error) {
	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list-reserve")
	updatedFiles, err := git.CloneOrPull(ubuntuRepoURL, dir, ubuntuDir)
	if err != nil {
		return nil, xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil, nil
	}

	rootDir := filepath.Join(dir, ubuntuDir)
	targets, err := util.FilterTargets(ubuntuDir, updatedFiles)
	if err != nil {
		return nil, xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log15.Debug("Ubuntu: no update file")
		return nil, nil
	}
	log15.Debug(fmt.Sprintf("Ubuntu updated files: %d", len(targets)))

	err = util.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		content, err := io.ReadAll(r)
		if err != nil {
			return err
		}

		cve := models.UbuntuCVEJSON{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
		}

		entries = append(entries, cve)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in Ubuntu walk: %w", err)
	}

	return entries, nil
}
