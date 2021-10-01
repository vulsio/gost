package db

import (
	"errors"
	"strings"

	"github.com/spf13/viper"
	"github.com/vulsio/gost/models"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
	"gorm.io/gorm"
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
func (r *RDBDriver) InsertUbuntu(cveJSONs []models.UbuntuCVEJSON) (err error) {
	cves := ConvertUbuntu(cveJSONs)
	if err = r.deleteAndInsertUbuntu(cves); err != nil {
		return xerrors.Errorf("Failed to insert Ubuntu CVE data. err: %s", err)
	}

	return nil
}

func (r *RDBDriver) deleteAndInsertUbuntu(cves []models.UbuntuCVE) (err error) {
	bar := pb.StartNew(len(cves))
	tx := r.conn.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuUpstreamLink{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuUpstreamLink. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuUpstream{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuUpstream. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuReleasePatch{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuReleasePatch. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuPatch{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuPatch. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuBug{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuBug. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuNote{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuNote. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuReference{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuReference. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuCVE{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete UbuntuCVE. err: %w", err)
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return xerrors.New("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for idx := range chunkSlice(len(cves), batchSize) {
		if err = tx.Create(cves[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	return nil
}

// ConvertUbuntu :
func ConvertUbuntu(cveJSONs []models.UbuntuCVEJSON) (cves []models.UbuntuCVE) {
	for _, cve := range cveJSONs {
		if strings.Contains(cve.Description, "** REJECT **") {
			continue
		}

		references := []models.UbuntuReference{}
		for _, r := range cve.References {
			references = append(references, models.UbuntuReference{Reference: r})
		}

		notes := []models.UbuntuNote{}
		for _, n := range cve.Notes {
			notes = append(notes, models.UbuntuNote{Note: n})
		}

		bugs := []models.UbuntuBug{}
		for _, b := range cve.Bugs {
			bugs = append(bugs, models.UbuntuBug{Bug: b})
		}

		patches := []models.UbuntuPatch{}
		for pkgName, p := range cve.Patches {
			var releasePatch []models.UbuntuReleasePatch
			for release, patch := range p {
				releasePatch = append(releasePatch, models.UbuntuReleasePatch{ReleaseName: release, Status: patch.Status, Note: patch.Note})
			}
			patches = append(patches, models.UbuntuPatch{PackageName: pkgName, ReleasePatches: releasePatch})
		}

		upstreams := []models.UbuntuUpstream{}
		for pkgName, u := range cve.UpstreamLinks {
			links := []models.UbuntuUpstreamLink{}
			for _, link := range u {
				links = append(links, models.UbuntuUpstreamLink{Link: link})
			}
			upstreams = append(upstreams, models.UbuntuUpstream{PackageName: pkgName, UpstreamLinks: links})
		}

		c := models.UbuntuCVE{
			PublicDateAtUSN:   cve.PublicDateAtUSN,
			CRD:               cve.CRD,
			Candidate:         cve.Candidate,
			PublicDate:        cve.PublicDate,
			References:        references,
			Description:       cve.Description,
			UbuntuDescription: cve.UbuntuDescription,
			Notes:             notes,
			Bugs:              bugs,
			Priority:          cve.Priority,
			DiscoveredBy:      cve.DiscoveredBy,
			AssignedTo:        cve.AssignedTo,
			Patches:           patches,
			Upstreams:         upstreams,
		}
		cves = append(cves, c)
	}

	return cves
}

var ubuntuVerCodename = map[string]string{
	"1404": "trusty",
	"1604": "xenial",
	"1804": "bionic",
	"2004": "focal",
	"2010": "groovy",
	"2104": "hirsute",
}

// GetUnfixedCvesUbuntu gets the CVEs related to debian_release.status IN ('needed', 'pending'), ver, pkgName.
func (r *RDBDriver) GetUnfixedCvesUbuntu(ver, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"needed", "pending"})
}

// GetFixedCvesUbuntu gets the CVEs related to debian_release.status IN ('released'), ver, pkgName.
func (r *RDBDriver) GetFixedCvesUbuntu(ver, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"released"})
}

func (r *RDBDriver) getCvesUbuntuWithFixStatus(ver, pkgName string, fixStatus []string) (map[string]models.UbuntuCVE, error) {
	codeName, ok := ubuntuVerCodename[ver]
	if !ok {
		return nil, xerrors.Errorf("Failed to convert from major version to codename. err: Ubuntu %s is not supported yet", ver)
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
			Preload("Patches.ReleasePatches", "release_name = ? AND status IN (?)", codeName, fixStatus).
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
