package db

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// GetUbuntu :
func (r *RDBDriver) GetUbuntu(cveID string) (*models.UbuntuCVE, error) {
	c := models.UbuntuCVE{}
	if err := r.conn.Where(&models.UbuntuCVE{Candidate: cveID}).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to get Ubuntu. err: %w", err)
	}

	if err := r.conn.Model(&c).Association("References").Find(&c.References); err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu.References. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Notes").Find(&c.Notes); err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu.Notes. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Bugs").Find(&c.Bugs); err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu.Bugs. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Patches").Find(&c.Patches); err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu.Patches. err: %w", err)
	}
	patches := []models.UbuntuPatch{}
	for _, p := range c.Patches {
		if err := r.conn.Model(&p).Association("ReleasePatches").Find(&p.ReleasePatches); err != nil {
			return nil, xerrors.Errorf("Failed to get Ubuntu.ReleasePatches. err: %w", err)
		}
		patches = append(patches, p)
	}
	c.Patches = patches
	if err := r.conn.Model(&c).Association("Upstreams").Find(&c.Upstreams); err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu.Upstreams. err: %w", err)
	}
	upstreams := []models.UbuntuUpstream{}
	for _, u := range c.Upstreams {
		if err := r.conn.Model(&u).Association("UpstreamLinks").Find(&u.UpstreamLinks); err != nil {
			return nil, xerrors.Errorf("Failed to get Ubuntu.UpstreamLinks err: %w", err)
		}
		upstreams = append(upstreams, u)
	}
	c.Upstreams = upstreams

	return &c, nil
}

// GetUbuntuMulti :
func (r *RDBDriver) GetUbuntuMulti(cveIDs []string) (map[string]models.UbuntuCVE, error) {
	m := map[string]models.UbuntuCVE{}
	for _, cveID := range cveIDs {
		cve, err := r.GetUbuntu(cveID)
		if err != nil {
			return nil, err
		}
		if cve != nil {
			m[cveID] = *cve
		}
	}
	return m, nil
}

// InsertUbuntu :
func (r *RDBDriver) InsertUbuntu(cves iter.Seq2[models.UbuntuCVE, error]) (err error) {
	if err = r.deleteAndInsertUbuntu(cves); err != nil {
		return xerrors.Errorf("Failed to insert Ubuntu CVE data. err: %s", err)
	}

	return nil
}

func (r *RDBDriver) deleteAndInsertUbuntu(cves iter.Seq2[models.UbuntuCVE, error]) (err error) {
	bar := pb.ProgressBarTemplate("{{counters .}} files processed. ({{speed .}})").New(0).Start().SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{models.UbuntuUpstreamLink{}, models.UbuntuUpstream{}, models.UbuntuReleasePatch{}, models.UbuntuPatch{}, models.UbuntuBug{}, models.UbuntuNote{}, models.UbuntuReference{}, models.UbuntuCVE{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return xerrors.New("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for chunk, err := range util.Chunk(cves, batchSize) {
		if err != nil {
			return xerrors.Errorf("failed to insert Ubuntu CVE data. err: %w", err)
		}

		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()

	return nil
}

var ubuntuVerCodename = map[string]string{
	"606":  "dapper",
	"610":  "edgy",
	"704":  "feisty",
	"710":  "gutsy",
	"804":  "hardy",
	"810":  "intrepid",
	"904":  "jaunty",
	"910":  "karmic",
	"1004": "lucid",
	"1010": "maverick",
	"1104": "natty",
	"1110": "oneiric",
	"1204": "precise",
	"1210": "quantal",
	"1304": "raring",
	"1310": "saucy",
	"1404": "trusty",
	"1410": "utopic",
	"1504": "vivid",
	"1510": "wily",
	"1604": "xenial",
	"1610": "yakkety",
	"1704": "zesty",
	"1710": "artful",
	"1804": "bionic",
	"1810": "cosmic",
	"1904": "disco",
	"1910": "eoan",
	"2004": "focal",
	"2010": "groovy",
	"2104": "hirsute",
	"2110": "impish",
	"2204": "jammy",
	"2210": "kinetic",
	"2304": "lunar",
	"2310": "mantic",
	"2404": "noble",
	"2410": "oracular",
}

// GetUnfixedCvesUbuntu gets the CVEs related to ubuntu_release_patches.status IN ('needed', 'deferred', 'pending'), ver, pkgName.
func (r *RDBDriver) GetUnfixedCvesUbuntu(ver, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"needed", "deferred", "pending"})
}

// GetFixedCvesUbuntu gets the CVEs related to ubuntu_release_patches.status IN ('released'), ver, pkgName.
func (r *RDBDriver) GetFixedCvesUbuntu(ver, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"released"})
}

func (r *RDBDriver) getCvesUbuntuWithFixStatus(ver, pkgName string, fixStatus []string) (map[string]models.UbuntuCVE, error) {
	codeName, ok := ubuntuVerCodename[ver]
	if !ok {
		return nil, xerrors.Errorf("Failed to convert from major version to codename. err: Ubuntu %s is not supported yet", ver)
	}
	esmCodeNames := []string{
		codeName,
		fmt.Sprintf("esm-apps/%s", codeName),
		fmt.Sprintf("esm-infra/%s", codeName),
		fmt.Sprintf("%s/esm", codeName),
		fmt.Sprintf("ros-esm/%s", codeName),
	}

	type Result struct {
		UbuntuCveID int64
	}

	results := []Result{}
	err := r.conn.
		Table("ubuntu_patches").
		Select("ubuntu_cve_id").
		Where("package_name = ?", pkgName).
		Scan(&results).Error

	if err != nil {
		if fixStatus[0] == "released" {
			return nil, xerrors.Errorf("Failed to get fixed cves of Ubuntu. err: %w", err)
		}
		return nil, xerrors.Errorf("Failed to get unfixed cves of Ubuntu. err: %w", err)
	}

	m := map[string]models.UbuntuCVE{}
	for _, res := range results {
		cve := models.UbuntuCVE{}
		if err := r.conn.
			Preload("Patches.ReleasePatches", "release_name IN (?) AND status IN (?)", esmCodeNames, fixStatus).
			Preload("Patches", "package_name = ?", pkgName).
			Where(&models.UbuntuCVE{ID: res.UbuntuCveID}).
			First(&cve).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, xerrors.Errorf("Failed to get UbuntuCVE. DB relationship may be broken, use `$ gost fetch ubuntu` to recreate DB. err: %w", err)
			}
			return nil, xerrors.Errorf("Failed to get UbuntuCVE. err: %w", err)
		}

		if err := r.conn.Model(&cve).Association("References").Find(&cve.References); err != nil {
			return nil, err
		}
		if err := r.conn.Model(&cve).Association("Notes").Find(&cve.Notes); err != nil {
			return nil, err
		}
		if err := r.conn.Model(&cve).Association("Bugs").Find(&cve.Bugs); err != nil {
			return nil, err
		}
		if err := r.conn.Model(&cve).Association("Upstreams").Find(&cve.Upstreams); err != nil {
			return nil, err
		}
		upstreams := []models.UbuntuUpstream{}
		for _, u := range cve.Upstreams {
			if err := r.conn.Model(&u).Association("UpstreamLinks").Find(&u.UpstreamLinks); err != nil {
				return nil, err
			}
			upstreams = append(upstreams, u)
		}
		cve.Upstreams = upstreams

		if len(cve.Patches) != 0 {
			for _, p := range cve.Patches {
				if len(p.ReleasePatches) != 0 {
					m[cve.Candidate] = cve
				}
			}
		}
	}

	return m, nil
}

// GetAdvisoriesUbuntu gets AdvisoryID: []CVE IDs
func (r *RDBDriver) GetAdvisoriesUbuntu() (map[string][]string, error) {
	m := map[string][]string{}
	var cs []models.UbuntuCVE
	// the maximum value of a host parameter number is SQLITE_MAX_VARIABLE_NUMBER, which defaults to 999 for SQLite versions prior to 3.32.0 (2020-05-22) or 32766 for SQLite versions after 3.32.0.
	// https://www.sqlite.org/limits.html Maximum Number Of Host Parameters In A Single SQL Statement
	if err := r.conn.Preload("References", "reference LIKE ?", "https://ubuntu.com/security/notices/USN-%").FindInBatches(&cs, 999, func(_ *gorm.DB, _ int) error {
		for _, c := range cs {
			for _, r := range c.References {
				m[strings.TrimPrefix(r.Reference, "https://ubuntu.com/security/notices/")] = append(m[strings.TrimPrefix(r.Reference, "https://ubuntu.com/security/notices/")], c.Candidate)
			}
		}
		return nil
	}).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get Ubuntu. err: %w", err)
	}

	for k := range m {
		m[k] = util.Unique(m[k])
	}

	return m, nil
}
