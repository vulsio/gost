package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/git"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	ubuntuRepoURL = "https://github.com/aquasecurity/vuln-list.git"
	ubuntuDir     = "ubuntu"
)

// FetchUbuntuVulnList clones vuln-list and returns CVE JSONs
func FetchUbuntuVulnList() (iter.Seq2[models.UbuntuCVEJSON, error], int, error) {
	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(ubuntuRepoURL, dir, ubuntuDir)
	if err != nil {
		return nil, 0, xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil, 0, nil
	}

	rootDir := filepath.Join(dir, ubuntuDir)
	targets, err := util.FilterTargets(ubuntuDir, updatedFiles)
	if err != nil {
		return nil, 0, xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log15.Debug("Ubuntu: no update file")
		return nil, 0, nil
	}
	log15.Debug(fmt.Sprintf("Ubuntu updated files: %d", len(targets)))

	count, err := countUbuntuCVEs(rootDir, targets)
	if err != nil {
		return nil, 0, xerrors.Errorf("failed to count Ubuntu CVEs: %w", err)
	}

	return func(yield func(models.UbuntuCVEJSON, error) bool) {

		err = util.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
			content, err := io.ReadAll(r)
			if err != nil {
				return err
			}

			cve := models.UbuntuCVEJSON{}
			if err = json.Unmarshal(content, &cve); err != nil {
				return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
			}

			if !yield(cve, nil) {
				return err
			}
			return nil
		})
		if err != nil && !yield(models.UbuntuCVEJSON{}, xerrors.Errorf("error in Ubuntu walk: %w", err)) {
			return
		}
	}, count, nil
}

func countUbuntuCVEs(rootDir string, targets map[string]struct{}) (int, error) {
	count := 0
	err := util.FileWalk(rootDir, targets, func(io.Reader, string) error {
		count++
		return nil
	})
	return count, err
}
