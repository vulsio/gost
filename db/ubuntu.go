package db

import (
	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func (r *RDBDriver) GetUbuntu(cveID string) *models.UbuntuCVE {
	c := models.UbuntuCVE{}
	var errs gorm.Errors
	errs = errs.Add(r.conn.Where(&models.UbuntuCVE{Candidate: cveID}).First(&c).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.References).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Notes).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Bugs).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Patches).Error)

	var patches []models.UbuntuPatch
	for _, p := range c.Patches {
		errs = errs.Add(r.conn.Model(&p).Related(&p.Patches).Error)
		patches = append(patches, p)
	}
	c.Patches = patches

	errs = errs.Add(r.conn.Model(&c).Related(&c.UpstreamLinks).Error)
	var upstreamLinks []models.UbuntuUpstream
	for _, u := range c.UpstreamLinks {
		errs = errs.Add(r.conn.Model(&u).Related(&u.Links).Error)
		upstreamLinks = append(upstreamLinks, u)
	}
	c.UpstreamLinks = upstreamLinks

	errs = util.DeleteRecordNotFound(errs)
	if len(errs.GetErrors()) > 0 {
		log15.Error("Failed to get Ubuntu", "err", errs.Error())
		return nil
	}

	return &c
}

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
	var errs gorm.Errors
	errs = errs.Add(tx.Delete(models.UbuntuUpstreamLink{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuUpstream{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuReleasePatch{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuPatch{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuBug{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuNote{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuReference{}).Error)
	errs = errs.Add(tx.Delete(models.UbuntuCVE{}).Error)
	errs = util.DeleteNil(errs)

	if len(errs.GetErrors()) > 0 {
		return xerrors.Errorf("Failed to delete old. err: %s", errs.Error())
	}

	for _, cve := range cves {
		if err = tx.Create(&cve).Error; err != nil {
			return xerrors.Errorf("Failed to insert. cve: %s, err: %s", cve.Candidate, err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func ConvertUbuntu(cveJSONs []models.UbuntuCVEJSON) (cves []models.UbuntuCVE) {
	for _, cve := range cveJSONs {
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
			patches = append(patches, models.UbuntuPatch{PackageName: pkgName, Patches: releasePatch})
		}

		var upstreamLinks []models.UbuntuUpstream
		for pkgName, u := range cve.UpstreamLinks {
			var links []models.UbuntuUpstreamLink
			for _, link := range u {
				links = append(links, models.UbuntuUpstreamLink{Link: link})
			}
			upstreamLinks = append(upstreamLinks, models.UbuntuUpstream{PackageName: pkgName, Links: links})
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
			UpstreamLinks:     upstreamLinks,
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

func (r *RDBDriver) GetUnfixedCvesUbuntu(major, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"needed", "pending"})
}

func (r *RDBDriver) GetFixedCvesUbuntu(major, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"released"})
}

func (r *RDBDriver) getCvesUbuntuWithFixStatus(major, pkgName string, fixStatus []string) map[string]models.UbuntuCVE {
	m := map[string]models.UbuntuCVE{}
	codeName, ok := ubuntuVerCodename[major]
	if !ok {
		log15.Error("Ubuntu %s is not supported yet", "err", major)
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
			Preload("Patches.Patches", "release_name = ? AND status IN (?)", codeName, fixStatus).
			Preload("Patches", "package_name = ?", pkgName).
			Where(&models.UbuntuCVE{ID: res.UbuntuCveID}).
			First(&cve).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			log15.Error("Failed to getCvesUbuntuWithFixStatus", "err", err)
			return m
		}

		// References, Notes, Bugs, UpstreamLinks
		var errs gorm.Errors
		errs = errs.Add(r.conn.Model(&cve).Related(&cve.References).Error)
		errs = errs.Add(r.conn.Model(&cve).Related(&cve.Notes).Error)
		errs = errs.Add(r.conn.Model(&cve).Related(&cve.Bugs).Error)

		errs = errs.Add(r.conn.Model(&cve).Related(&cve.UpstreamLinks).Error)
		var upstreamLinks []models.UbuntuUpstream
		for _, u := range cve.UpstreamLinks {
			errs = errs.Add(r.conn.Model(&u).Related(&u.Links).Error)
			upstreamLinks = append(upstreamLinks, u)
		}
		cve.UpstreamLinks = upstreamLinks

		errs = util.DeleteRecordNotFound(errs)
		if len(errs.GetErrors()) > 0 {
			log15.Error("Failed to get Ubuntu", "err", errs.Error())
			return map[string]models.UbuntuCVE{}
		}

		if len(cve.Patches) != 0 {
			for _, p := range cve.Patches {
				if len(p.Patches) != 0 {
					m[cve.Candidate] = cve
				}
			}
		}
	}

	return m
}
