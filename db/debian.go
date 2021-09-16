package db

import (
	"errors"
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	pb "gopkg.in/cheggaaa/pb.v1"
	"gorm.io/gorm"
)

// GetDebian :
func (r *RDBDriver) GetDebian(cveID string) *models.DebianCVE {
	c := models.DebianCVE{}
	err := r.conn.Where(&models.DebianCVE{CveID: cveID}).First(&c).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log15.Error("Failed to get Debian", "err", err)
		return nil
	}
	err = r.conn.Model(&c).Association("Package").Find(&c.Package)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log15.Error("Failed to get Debian", "err", err)
		return nil
	}

	var newPkg []models.DebianPackage
	for _, pkg := range c.Package {
		err = r.conn.Model(&pkg).Association("Release").Find(&pkg.Release)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			log15.Error("Failed to get Debian", "err", err)
			return nil
		}
		newPkg = append(newPkg, pkg)
	}
	c.Package = newPkg
	return &c
}

// InsertDebian :
func (r *RDBDriver) InsertDebian(cveJSON models.DebianJSON) (err error) {
	cves := ConvertDebian(cveJSON)
	if err = r.deleteAndInsertDebian(r.conn, cves); err != nil {
		return fmt.Errorf("Failed to insert Debian CVE data. err: %s", err)
	}
	return nil
}
func (r *RDBDriver) deleteAndInsertDebian(conn *gorm.DB, cves []models.DebianCVE) (err error) {
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
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.DebianRelease{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.DebianPackage{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.DebianCVE{}).Error)
	errs = util.DeleteNil(errs)

	if len(errs.GetErrors()) > 0 {
		return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
	}

	for idx := range chunkSlice(len(cves), r.batchSize) {
		if err = tx.Create(cves[idx.From:idx.To]).Error; err != nil {
			return fmt.Errorf("Failed to insert. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	return nil
}

// ConvertDebian :
func ConvertDebian(cveJSONs models.DebianJSON) (cves []models.DebianCVE) {
	uniqCve := map[string]models.DebianCVE{}
	for pkgName, cveMap := range cveJSONs {
		for cveID, cve := range cveMap {
			var releases []models.DebianRelease
			for release, releaseInfo := range cve.Releases {
				r := models.DebianRelease{
					ProductName:  release,
					Status:       releaseInfo.Status,
					FixedVersion: releaseInfo.FixedVersion,
					Urgency:      releaseInfo.Urgency,
					Version:      releaseInfo.Repositories[release],
				}
				releases = append(releases, r)
			}

			pkg := models.DebianPackage{
				PackageName: pkgName,
				Release:     releases,
			}

			pkgs := []models.DebianPackage{pkg}
			if oldCve, ok := uniqCve[cveID]; ok {
				pkgs = append(pkgs, oldCve.Package...)
			}

			uniqCve[cveID] = models.DebianCVE{
				CveID:       cveID,
				Scope:       cve.Scope,
				Description: cve.Description,
				Package:     pkgs,
			}
		}
	}
	for _, c := range uniqCve {
		cves = append(cves, c)
	}
	return cves
}

var debVerCodename = map[string]string{
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
}

// GetUnfixedCvesDebian gets the CVEs related to debian_release.status = 'open', major, pkgName.
func (r *RDBDriver) GetUnfixedCvesDebian(major, pkgName string) map[string]models.DebianCVE {
	return r.getCvesDebianWithFixStatus(major, pkgName, "open")
}

// GetFixedCvesDebian gets the CVEs related to debian_release.status = 'resolved', major, pkgName.
func (r *RDBDriver) GetFixedCvesDebian(major, pkgName string) map[string]models.DebianCVE {
	return r.getCvesDebianWithFixStatus(major, pkgName, "resolved")
}

func (r *RDBDriver) getCvesDebianWithFixStatus(major, pkgName, fixStatus string) map[string]models.DebianCVE {
	m := map[string]models.DebianCVE{}
	codeName, ok := debVerCodename[major]
	if !ok {
		log15.Error("Debian %s is not supported yet", "err", major)
		return m
	}

	type Result struct {
		DebianCveID int64
	}

	results := []Result{}
	err := r.conn.
		Table("debian_packages").
		Select("debian_cve_id").
		Where("package_name = ?", pkgName).
		Scan(&results).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		if fixStatus == "open" {
			log15.Error("Failed to get unfixed cves of Debian", "err", err)
		} else {
			log15.Error("Failed to get fixed cves of Debian", "err", err)
		}
		return m
	}

	for _, res := range results {
		debcve := models.DebianCVE{}
		err := r.conn.
			Preload("Package.Release", "status = ? AND product_name = ?", fixStatus, codeName).
			Preload("Package", "package_name = ?", pkgName).
			Where(&models.DebianCVE{ID: res.DebianCveID}).
			First(&debcve).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			log15.Error("Failed to get DebianCVE", res.DebianCveID, err)
			return m
		}

		if len(debcve.Package) != 0 {
			for _, pkg := range debcve.Package {
				if len(pkg.Release) != 0 {
					m[debcve.CveID] = debcve
				}

			}
		}
	}

	return m
}
