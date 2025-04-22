package fetcher

import (
	"encoding/json"
	"errors"
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
func FetchUbuntuVulnList() (iter.Seq2[models.UbuntuCVEJSON, error], error) {
	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list")
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

	return func(yield func(models.UbuntuCVEJSON, error) bool) {
		var yieldErr = errors.New("yield error")
		err = util.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
			cve := models.UbuntuCVEJSON{}
			if err = json.NewDecoder(r).Decode(&cve); err != nil {
				return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
			}

			if !yield(cve, nil) {
				return yieldErr
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, yieldErr) { // No need to call yield with error
				return
			}
			if !yield(models.UbuntuCVEJSON{}, xerrors.Errorf("error in Ubuntu walk: %w", err)) {
				return
			}
		}
	}, nil
}
