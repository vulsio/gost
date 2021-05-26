package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/git"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	"golang.org/x/xerrors"
)

const (
	ubuntuDir = "ubuntu"
)

// FetchUbuntuVulnList clones vuln-list and returns CVE JSONs
func FetchUbuntuVulnList() (entries []models.UbuntuCVEJSON, err error) {
	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(repoURL, dir)
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
		content, err := ioutil.ReadAll(r)
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
