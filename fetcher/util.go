package fetcher

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/vulsio/gost/util"
)

func fetchGitArchive(url, fetchDir, targetDirPrefix string) error {
	if err := os.RemoveAll(fetchDir); err != nil {
		return xerrors.Errorf("Failed to remove directory: %w", err)
	}

	bs, err := util.FetchURL(url)
	if err != nil {
		return xerrors.Errorf("Failed to fetch git archive: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return xerrors.Errorf("Failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("Failed to read tar header: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			if !strings.HasPrefix(hdr.Name, targetDirPrefix) {
				break
			}

			filePath := filepath.Join(fetchDir, hdr.Name)

			if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
				return xerrors.Errorf("Failed to create directory: %w", err)
			}

			if err := func() error {
				f, err := os.Create(filePath)
				if err != nil {
					return xerrors.Errorf("Failed to create file: %w", err)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return xerrors.Errorf("Failed to write file: %w", err)
				}

				return nil
			}(); err != nil {
				return xerrors.Errorf("Failed to create file: %w", err)
			}
		default:
		}
	}

	return nil
}
