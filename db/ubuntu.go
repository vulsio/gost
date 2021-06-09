package db

import (
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
	"gorm.io/gorm"
)

// GetUbuntu :
func (r *RDBDriver) GetUbuntu(cveID string) *models.UbuntuCVE {
	c := models.UbuntuCVE{}
	var errs util.Errors
	errs = errs.Add(r.conn.Where(&models.UbuntuCVE{Candidate: cveID}).First(&c).Error)
	errs = errs.Add(r.conn.Model(&c).Association("References").Find(&c.References))
	errs = errs.Add(r.conn.Model(&c).Association("Notes").Find(&c.Notes))
	errs = errs.Add(r.conn.Model(&c).Association("Bugs").Find(&c.Bugs))
	errs = errs.Add(r.conn.Model(&c).Association("Patches").Find(&c.Patches))

	var patches []models.UbuntuPatch
	for _, p := range c.Patches {
		errs = errs.Add(r.conn.Model(&p).Association("ReleasePatches").Find(&p.ReleasePatches))
		patches = append(patches, p)
	}
	c.Patches = patches

	errs = errs.Add(r.conn.Model(&c).Association("Upstreams").Find(&c.Upstreams))
	var upstreams []models.UbuntuUpstream
	for _, u := range c.Upstreams {
		errs = errs.Add(r.conn.Model(&u).Association("UpstreamLinks").Find(&u.UpstreamLinks))
		upstreams = append(upstreams, u)
	}
	c.Upstreams = upstreams

	errs = util.DeleteRecordNotFound(errs)
	if len(errs.GetErrors()) > 0 {
		log15.Error("Failed to get Ubuntu", "err", errs.Error())
		return nil
	}

	return &c
}

// InsertUbuntu :
func (r *RDBDriver) InsertUbuntu(cveJSONs []models.UbuntuCVEJSON) (err error) {
	cves := ConvertUbuntu(cveJSONs)
	if err = r.deleteAndInsertUbuntu(r.conn, cves); err != nil {
		return xerrors.Errorf("Failed to insert Ubuntu CVE data. err: %s", err)
	}

	return nil
}

func (r *RDBDriver) deleteAndInsertUbuntu(conn *gorm.DB, cves []models.UbuntuCVE) (err error) {
	bar := pb.StartNew(len(cves))
	tx := conn.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	var errs util.Errors
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuUpstreamLink{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuUpstream{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuReleasePatch{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuPatch{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuBug{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuNote{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuReference{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.UbuntuCVE{}).Error)
	errs = util.DeleteNil(errs)

	if len(errs.GetErrors()) > 0 {
		return xerrors.Errorf("Failed to delete old. err: %s", errs.Error())
	}

	for idx := range chunkSlice(len(cves), 15) {
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

		var references []models.UbuntuReference
		for _, r := range cve.References {
			references = append(references, models.UbuntuReference{Reference: r})
		}

		var notes []models.UbuntuNote
		for _, n := range cve.Notes {
			notes = append(notes, models.UbuntuNote{Note: n})
		}

		var bugs []models.UbuntuBug
		for _, b := range cve.Bugs {
			bugs = append(bugs, models.UbuntuBug{Bug: b})
		}

		var patches []models.UbuntuPatch
		for pkgName, p := range cve.Patches {
			var releasePatch []models.UbuntuReleasePatch
			for release, patch := range p {
				releasePatch = append(releasePatch, models.UbuntuReleasePatch{ReleaseName: release, Status: patch.Status, Note: patch.Note})
			}
			patches = append(patches, models.UbuntuPatch{PackageName: pkgName, ReleasePatches: releasePatch})
		}

		var upstreams []models.UbuntuUpstream
		for pkgName, u := range cve.UpstreamLinks {
			var links []models.UbuntuUpstreamLink
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
func (r *RDBDriver) GetUnfixedCvesUbuntu(ver, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"needed", "pending"})
}

// GetFixedCvesUbuntu gets the CVEs related to debian_release.status IN ('released'), ver, pkgName.
func (r *RDBDriver) GetFixedCvesUbuntu(ver, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(ver, pkgName, []string{"released"})
}

func (r *RDBDriver) getCvesUbuntuWithFixStatus(ver, pkgName string, fixStatus []string) map[string]models.UbuntuCVE {
	m := map[string]models.UbuntuCVE{}
	codeName, ok := ubuntuVerCodename[ver]
	if !ok {
		log15.Error("Ubuntu %s is not supported yet", "err", ver)
		return m
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

	if err != nil && err != gorm.ErrRecordNotFound {
		if fixStatus[0] == "released" {
			log15.Error("Failed to get fixed cves of Ubuntu", "err", err)
		} else {
			log15.Error("Failed to get unfixed cves of Ubuntu", "err", err)
		}
	}

	for _, res := range results {
		cve := models.UbuntuCVE{}
		err := r.conn.
			Preload("Patches.ReleasePatches", "release_name = ? AND status IN (?)", codeName, fixStatus).
			Preload("Patches", "package_name = ?", pkgName).
			Where(&models.UbuntuCVE{ID: res.UbuntuCveID}).
			First(&cve).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			log15.Error("Failed to getCvesUbuntuWithFixStatus", "err", err)
			return m
		}

		var errs util.Errors
		errs = errs.Add(r.conn.Model(&cve).Association("References").Find(&cve.References))
		errs = errs.Add(r.conn.Model(&cve).Association("Notes").Find(&cve.Notes))
		errs = errs.Add(r.conn.Model(&cve).Association("Bugs").Find(&cve.Bugs))

		errs = errs.Add(r.conn.Model(&cve).Association("Upstreams").Find(&cve.Upstreams))
		var upstreams []models.UbuntuUpstream
		for _, u := range cve.Upstreams {
			errs = errs.Add(r.conn.Model(&u).Association("UpstreamLinks").Find(&u.UpstreamLinks))
			upstreams = append(upstreams, u)
		}
		cve.Upstreams = upstreams

		errs = util.DeleteRecordNotFound(errs)
		if len(errs.GetErrors()) > 0 {
			log15.Error("Failed to get Ubuntu", "err", errs.Error())
			return map[string]models.UbuntuCVE{}
		}

		if len(cve.Patches) != 0 {
			for _, p := range cve.Patches {
				if len(p.ReleasePatches) != 0 {
					m[cve.Candidate] = cve
				}
			}
		}
	}

	return m
}
