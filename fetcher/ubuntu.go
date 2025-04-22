package fetcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	ubuntuRepoURL = "https://github.com/aquasecurity/vuln-list/archive/refs/heads/main.tar.gz"
	ubuntuDir     = "ubuntu"
)

// FetchUbuntuVulnList clones vuln-list and returns CVE JSONs
func FetchUbuntuVulnList() (iter.Seq2[models.UbuntuCVEJSON, error], error) {
	if err := fetchGitArchive(ubuntuRepoURL, filepath.Join(util.CacheDir(), "vuln-list"), fmt.Sprintf("vuln-list-main/%s", ubuntuDir)); err != nil {
		return nil, xerrors.Errorf("Failed to fetch vuln-list-ubuntu: %w", err)
	}

	return func(yield func(models.UbuntuCVEJSON, error) bool) {
		var yieldErr = errors.New("yield error")
		if err := filepath.WalkDir(filepath.Join(util.CacheDir(), "vuln-list"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return xerrors.Errorf("Failed to open file: %w", err)
			}
			defer f.Close()

			cve := models.UbuntuCVEJSON{}
			if err = json.NewDecoder(f).Decode(&cve); err != nil {
				return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
			}

			if !yield(cve, nil) {
				return yieldErr
			}

			return nil
		}); err != nil {
			if errors.Is(err, yieldErr) { // No need to call yield with error
				return
			}
			if !yield(models.UbuntuCVEJSON{}, xerrors.Errorf("Failed to walk %s: %w", filepath.Join(util.CacheDir(), "vuln-list"), err)) {
				return
			}
		}
	}, nil
}
