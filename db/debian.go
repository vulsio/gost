package db

import (
	"errors"
	"fmt"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
)

// GetDebian :
func (r *RDBDriver) GetDebian(cveID string) (*models.DebianCVE, error) {
	c := models.DebianCVE{}
	if err := r.conn.Where(&models.DebianCVE{CveID: cveID}).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to get Debian. err: %w", err)
	}

	if err := r.conn.Model(&c).Association("Package").Find(&c.Package); err != nil {
		return nil, xerrors.Errorf("Failed to get Debian.Package. err: %w", err)
	}

	newPkg := []models.DebianPackage{}
	for _, pkg := range c.Package {
		if err := r.conn.Model(&pkg).Association("Release").Find(&pkg.Release); err != nil {
			return nil, xerrors.Errorf("Failed to get Debian.Package.Release. err: %w", err)
		}
		newPkg = append(newPkg, pkg)
	}
	c.Package = newPkg
	return &c, nil
}

// GetDebianMulti :
func (r *RDBDriver) GetDebianMulti(cveIDs []string) (map[string]models.DebianCVE, error) {
	m := map[string]models.DebianCVE{}
	for _, cveID := range cveIDs {
		cve, err := r.GetDebian(cveID)
		if err != nil {
			return nil, err
		}
		if cve != nil {
			m[cve.CveID] = *cve
		}
	}
	return m, nil
}

// InsertDebian :
func (r *RDBDriver) InsertDebian(cves []models.DebianCVE) (err error) {
	if err = r.deleteAndInsertDebian(cves); err != nil {
		return xerrors.Errorf("Failed to insert Debian CVE data. err: %w", err)
	}
	return nil
}
func (r *RDBDriver) deleteAndInsertDebian(cves []models.DebianCVE) (err error) {
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
	for _, table := range []interface{}{models.DebianRelease{}, models.DebianPackage{}, models.DebianCVE{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
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

var debVerCodename = map[string]string{
	"7":  "wheezy",
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
}

// GetUnfixedCvesDebian gets the CVEs related to debian_release.status = 'open', major, pkgName.
func (r *RDBDriver) GetUnfixedCvesDebian(major, pkgName string) (map[string]models.DebianCVE, error) {
	return r.getCvesDebianWithFixStatus(major, pkgName, "open")
}

// GetFixedCvesDebian gets the CVEs related to debian_release.status = 'resolved', major, pkgName.
func (r *RDBDriver) GetFixedCvesDebian(major, pkgName string) (map[string]models.DebianCVE, error) {
	return r.getCvesDebianWithFixStatus(major, pkgName, "resolved")
}

func (r *RDBDriver) getCvesDebianWithFixStatus(major, pkgName, fixStatus string) (map[string]models.DebianCVE, error) {
	codeName, ok := debVerCodename[major]
	if !ok {
		return nil, xerrors.Errorf("Failed to convert from major version to codename. err: Debian %s is not supported yet", major)
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

	if err != nil {
		if fixStatus == "open" {
			return nil, xerrors.Errorf("Failed to get unfixed cves of Debian: %w", err)
		}
		return nil, xerrors.Errorf("Failed to get fixed cves of Debian. err: %w", err)
	}

	m := map[string]models.DebianCVE{}
	for _, res := range results {
		debcve := models.DebianCVE{}
		if err := r.conn.
			Preload("Package.Release", "status = ? AND product_name = ?", fixStatus, codeName).
			Preload("Package", "package_name = ?", pkgName).
			Where(&models.DebianCVE{ID: res.DebianCveID}).
			First(&debcve).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, xerrors.Errorf("Failed to get DebianCVE. DB relationship may be broken, use `$ gost fetch debian` to recreate DB. err: %w", err)
			}
			return nil, xerrors.Errorf("Failed to get DebianCVE. DebianCveID: %d, err: %w", res.DebianCveID, err)
		}

		if len(debcve.Package) != 0 {
			for _, pkg := range debcve.Package {
				if len(pkg.Release) != 0 {
					m[debcve.CveID] = debcve
				}

			}
		}
	}

	return m, nil
}
