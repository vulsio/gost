package fetcher

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// RetrieveDebianCveDetails returns CVE details
func RetrieveDebianCveDetails() (models.DebianJSON, error) {
	cves, err := retrieveDebianSecurityTrackerAPI()
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CVE details from Debian Security Tracker API. err: %w", err)
	}

	cvesTrivyDB, err := retrieveTrivyDB()
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CVE details from Trivy-DB. err: %w", err)
	}

	for pkg, cvemap := range cvesTrivyDB {
		if cves[pkg] == nil {
			cves[pkg] = models.DebianCveMap{}
		}
		for cve, e := range cvemap {
			cm := cves[pkg][cve]
			if cm.Description == "" {
				cm.Description = e.Description
			}
			if cm.Releases == nil {
				cm.Releases = map[string]models.DebianReleaseJSON{}
			}
			for codename, r := range e.Releases {
				if _, ok := cm.Releases[codename]; !ok {
					cm.Releases[codename] = r
				}
			}
			cves[pkg][cve] = cm
		}
	}

	return cves, nil
}

func retrieveDebianSecurityTrackerAPI() (models.DebianJSON, error) {
	resp, err := util.FetchURL("https://security-tracker.debian.org/tracker/data/json")
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch cve data from Debian Security Tracker API. err: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("Failed to fetch cve data from Debian Security Tracker API. err: status code: %d", resp.StatusCode)
	}

	var cves models.DebianJSON
	if err := json.NewDecoder(resp.Body).Decode(&cves); err != nil {
		return nil, xerrors.Errorf("Failed to decode Debian JSON. err: %w", err)
	}

	return cves, nil
}

func retrieveTrivyDB() (models.DebianJSON, error) {
	ctx := context.Background()

	// $ oras manifest fetch --media-type "application/vnd.oci.image.manifest.v1+json" ghcr.io/aquasecurity/trivy-db:latest
	// {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.aquasec.trivy.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[{"mediaType":"application/vnd.aquasec.trivy.db.layer.v1.tar+gzip","digest":"sha256:4659ee8e31616ad4cf61d0e71add03bbb39fd61a778b692d29b90b95bbfab0ec","size":39679068,"annotations":{"org.opencontainers.image.title":"db.tar.gz"}}],"annotations":{"org.opencontainers.image.created":"2023-06-22T18:07:53Z"}}
	d, err := fetchManifest(ctx)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch manifest. err: %w", err)
	}

	// oras blob fetch --output ${cache dir}/db.tar.gz ghcr.io/aquasecurity/trivy-db@sha256:0ecd2dfd4f851f49167b98f3aaf73e67d704d006c58bc3ac41a9f19a9731163
	// tar zfx db.tar.gz trivy.db
	dbpath, err := fetchBlob(ctx, d)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch blob. err: %w", err)
	}

	return walkDB(dbpath)
}

func fetchManifest(ctx context.Context) (ocispec.Descriptor, error) {
	src, err := remote.NewRepository("ghcr.io/aquasecurity/trivy-db")
	if err != nil {
		return ocispec.Descriptor{}, xerrors.Errorf("Failed to create client to ghcr.io/aquasecurity/trivy-db. err: %w", err)
	}
	src.ManifestMediaTypes = []string{"application/vnd.oci.image.manifest.v1+json"}

	desc, rc, err := src.FetchReference(ctx, "latest")
	if err != nil {
		return ocispec.Descriptor{}, xerrors.Errorf("Failed to fetch the manifest identified by the reference. err: %w", err)
	}
	defer rc.Close()

	bs, err := content.ReadAll(rc, desc)
	if err != nil {
		return ocispec.Descriptor{}, xerrors.Errorf("Failed to read content. err: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(bs, &manifest); err != nil {
		return ocispec.Descriptor{}, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
	}

	for _, l := range manifest.Layers {
		if l.MediaType == "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip" {
			return l, nil
		}
	}
	return ocispec.Descriptor{}, xerrors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
}

func fetchBlob(ctx context.Context, desc ocispec.Descriptor) (string, error) {
	src, err := remote.NewRepository("ghcr.io/aquasecurity/trivy-db")
	if err != nil {
		return "", xerrors.Errorf("Failed to create client to ghcr.io/aquasecurity/trivy-db. err: %w", err)
	}

	rc, err := src.Fetch(ctx, desc)
	if err != nil {
		return "", xerrors.Errorf("Failed to fetch the manifest identified by the reference. err: %w", err)
	}
	defer rc.Close()

	bs, err := content.ReadAll(rc, desc)
	if err != nil {
		return "", xerrors.Errorf("Failed to read content. err: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return "", xerrors.Errorf("Failed to create new gzip reader. err: %w", err)
	}

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}

		if header.Name == "trivy.db" {
			p := filepath.Join(util.CacheDir(), "trivy.db")
			if err := func(dbpath string) error {
				if err := os.MkdirAll(util.CacheDir(), 0700); err != nil {
					return xerrors.Errorf("Failed to mkdir %s: %w", util.CacheDir(), err)
				}

				f, err := os.Create(dbpath)
				if err != nil {
					return xerrors.Errorf("Failed to create %s. err: %w", p, err)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return xerrors.Errorf("Failed to copy from src to dst. err: %w", err)
				}

				return nil
			}(p); err != nil {
				return "", xerrors.Errorf("Failed to create trivy.db. err: %w", err)
			}
			return p, nil
		}
	}

	return "", xerrors.Errorf("not found trivy.db in ghcr.io/aquasecurity/trivy-db@%s", desc.Digest.String())
}

func walkDB(dbpath string) (models.DebianJSON, error) {
	debVerCodename := map[string]string{
		"7":  "wheezy",
		"8":  "jessie",
		"9":  "stretch",
		"10": "buster",
		"11": "bullseye",
		"12": "bookworm",
		"13": "trixie",
	}

	cves := models.DebianJSON{}

	db, err := bolt.Open(dbpath, 0600, nil)
	if err != nil {
		return nil, xerrors.Errorf("Failed to open db. err: %w", err)
	}
	defer db.Close()

	if err := db.View(func(tx *bolt.Tx) error {
		ds := map[string]string{}
		if err := tx.Bucket([]byte("vulnerability")).ForEach(func(cve, bs []byte) error {
			var v types.Vulnerability
			if err := json.Unmarshal(bs, &v); err != nil {
				return xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			ds[string(cve)] = v.Description

			return nil
		}); err != nil {
			return xerrors.Errorf("Failed to foreach vulnerability. err: %w", err)
		}

		if err := tx.ForEach(func(bn []byte, b *bolt.Bucket) error {
			s := string(bn)
			if !strings.HasPrefix(s, "debian ") {
				return nil
			}

			codename, ok := debVerCodename[strings.TrimPrefix(s, "debian ")]
			if !ok {
				return xerrors.Errorf("not found debian major version. actual: %s", strings.TrimPrefix(s, "debian "))
			}

			if err := b.ForEachBucket(func(pkg []byte) error {
				if err := b.Bucket(pkg).ForEach(func(cve, bs []byte) error {
					var a types.Advisory
					if err := json.Unmarshal(bs, &a); err != nil {
						return xerrors.Errorf("Failed to unmarshal json. err: %w", err)
					}

					if cves[string(pkg)] == nil {
						cves[string(pkg)] = models.DebianCveMap{}
					}
					cm := cves[string(pkg)][string(cve)]
					cm.Description = ds[string(cve)]
					if cm.Releases == nil {
						cm.Releases = map[string]models.DebianReleaseJSON{}
					}

					status := "open"
					if a.FixedVersion != "" {
						status = "resolved"
					}
					urgency := strings.ToLower(a.Severity.String())
					if urgency == "unknown" && a.State != "" {
						urgency = a.State
					}
					r := models.DebianReleaseJSON{
						Status:       status,
						FixedVersion: a.FixedVersion,
						Urgency:      urgency,
					}
					cm.Releases[codename] = r

					cves[string(pkg)][string(cve)] = cm

					return nil
				}); err != nil {
					return xerrors.Errorf("Failed to foreach %s. err: %w", string(pkg), err)
				}
				return nil
			}); err != nil {
				return xerrors.Errorf("Failed to foreach %s. err: %w", string(bn), err)
			}
			return nil
		}); err != nil {
			return xerrors.Errorf("Failed to foreach. err: %w", err)
		}
		return nil
	}); err != nil {
		return nil, xerrors.Errorf("Failed to view db. err: %w", err)
	}

	return cves, nil
}
