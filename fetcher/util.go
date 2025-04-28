package fetcher

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/vulsio/gost/util"
)

func fetchGitArchive(url, fetchDir, targetDirPrefix string) error {
	if err := os.RemoveAll(fetchDir); err != nil {
		return xerrors.Errorf("Failed to remove directory. err: %w", err)
	}

	resp, err := util.FetchURL(url)
	if err != nil {
		return xerrors.Errorf("Failed to fetch git archive. err: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("Failed to fetch git archive. err: status code: %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("Failed to create gzip reader. err: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("Failed to read tar header. err: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			if !strings.HasPrefix(hdr.Name, targetDirPrefix) {
				break
			}

			filePath := filepath.Join(fetchDir, hdr.Name)

			if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
				return xerrors.Errorf("Failed to create directory. err: %w", err)
			}

			if err := func() error {
				f, err := os.Create(filePath)
				if err != nil {
					return xerrors.Errorf("Failed to create file. err: %w", err)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return xerrors.Errorf("Failed to write file. err: %w", err)
				}

				return nil
			}(); err != nil {
				return xerrors.Errorf("Failed to create file. err: %w", err)
			}
		default:
		}
	}

	return nil
}
