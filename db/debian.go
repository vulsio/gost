package db

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func (r *RDBDriver) GetDebian(cveID string) *models.DebianCVE {
	c := models.DebianCVE{}
	err := r.conn.Where(&models.DebianCVE{CveID: cveID}).First(&c).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		log15.Error("Failed to get Debian", "err", err)
		return nil
	}
	err = r.conn.Model(&c).Related(&c.Package).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		log15.Error("Failed to get Debian", "err", err)
		return nil
	}

	var newPkg []models.DebianPackage
	for _, pkg := range c.Package {
		err = r.conn.Model(&pkg).Related(&pkg.Release).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			log15.Error("Failed to get Debian", "err", err)
			return nil
		}
		newPkg = append(newPkg, pkg)
	}
	c.Package = newPkg
	return &c
}

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
	var errs gorm.Errors
	errs = errs.Add(tx.Delete(models.DebianRelease{}).Error)
	errs = errs.Add(tx.Delete(models.DebianPackage{}).Error)
	errs = errs.Add(tx.Delete(models.DebianCVE{}).Error)
	errs = util.DeleteNil(errs)

	if len(errs.GetErrors()) > 0 {
		return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
	}

	for _, cve := range cves {
		if err = tx.Create(&cve).Error; err != nil {
			return fmt.Errorf("Failed to insert. cve: %s, err: %s", cve.CveID, err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

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
}

func (r *RDBDriver) GetUnfixedCvesDebian(major, pkgName string) map[string]models.DebianCVE {
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
	err := r.conn.Table("debian_releases").
		Select("debian_cve_id").
		Joins("join debian_packages on debian_releases.debian_package_id = debian_packages.id AND debian_packages.package_name = ?", pkgName).
		Where(&models.DebianRelease{
			ProductName: codeName,
			Status:      "open",
		}).Scan(&results).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		log15.Error("Failed to get unfixed cves of Debian", "err", err)
		return m
	}

	for _, res := range results {
		debcve := models.DebianCVE{}
		err = r.conn.
			Preload("Package").
			Where(&models.DebianCVE{ID: res.DebianCveID}).First(&debcve).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			log15.Error("Failed to get DebianCVE", res.DebianCveID, err)
			return m
		}

		pkgs := []models.DebianPackage{}
		for _, pkg := range debcve.Package {
			if pkg.PackageName != pkgName {
				continue
			}
			err = r.conn.Model(&pkg).Related(&pkg.Release).Error
			if err != nil && err != gorm.ErrRecordNotFound {
				log15.Error("Failed to get DebianRelease", pkg.Release, err)
				return m
			}

			rels := []models.DebianRelease{}
			for _, rel := range pkg.Release {
				if rel.ProductName == codeName && rel.Status == "open" {
					rels = append(rels, rel)
				}
			}
			if len(rels) == 0 {
				continue
			}
			pkg.Release = rels
			pkgs = append(pkgs, pkg)
		}
		if len(pkgs) != 0 {
			debcve.Package = pkgs
			m[debcve.CveID] = debcve
		}
	}
	return m
}
