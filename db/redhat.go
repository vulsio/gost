package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
)

// GetAfterTimeRedhat :
func (r *RDBDriver) GetAfterTimeRedhat(after time.Time) (allCves []models.RedhatCVE, err error) {
	all := []models.RedhatCVE{}
	if err = r.conn.Where("public_date >= ?", after.Format("2006-01-02")).Find(&all).Error; err != nil {
		return nil, err
	}

	// TODO: insufficient
	for _, a := range all {
		if err = r.conn.Model(&a).Association("Cvss3").Find(&a.Cvss3); err != nil {
			return nil, err
		}
		if err = r.conn.Model(&a).Association("Details").Find(&a.Details); err != nil {
			return nil, err
		}
		if err = r.conn.Model(&a).Association("PackageState").Find(&a.PackageState); err != nil {
			return nil, err
		}
		allCves = append(allCves, a)
	}
	return allCves, nil
}

// GetRedhat :
func (r *RDBDriver) GetRedhat(cveID string) (*models.RedhatCVE, error) {
	c := models.RedhatCVE{}
	if err := r.conn.Where(&models.RedhatCVE{Name: cveID}).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to get Redhat. err: %w", err)
	}

	if err := r.conn.Model(&c).Association("Details").Find(&c.Details); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.Details. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("References").Find(&c.References); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.References. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Bugzilla").Find(&c.Bugzilla); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.Bugzilla. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Cvss").Find(&c.Cvss); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.Cvss. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("Cvss3").Find(&c.Cvss3); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.Cvss3. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("AffectedRelease").Find(&c.AffectedRelease); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.AffectedRelease. err: %w", err)
	}
	if err := r.conn.Model(&c).Association("PackageState").Find(&c.PackageState); err != nil {
		return nil, xerrors.Errorf("Failed to get Redhat.PackageState. err: %w", err)
	}
	return &c, nil
}

// GetRedhatMulti :
func (r *RDBDriver) GetRedhatMulti(cveIDs []string) (map[string]models.RedhatCVE, error) {
	m := map[string]models.RedhatCVE{}
	for _, cveID := range cveIDs {
		cve, err := r.GetRedhat(cveID)
		if err != nil {
			return nil, err
		}
		if cve != nil {
			m[cveID] = *cve
		}
	}
	return m, nil
}

// GetUnfixedCvesRedhat gets the unfixed CVEs.
func (r *RDBDriver) GetUnfixedCvesRedhat(version, pkgName string, ignoreWillNotFix bool) (map[string]models.RedhatCVE, error) {
	m := map[string]models.RedhatCVE{}
	var cpe string
	if strings.HasSuffix(version, "-eus") {
		cpe = fmt.Sprintf("cpe:/o:redhat:rhel_eus:%s", strings.TrimSuffix(version, "-eus"))
	} else if strings.HasSuffix(version, "-aus") {
		cpe = fmt.Sprintf("cpe:/o:redhat:rhel_aus:%s", strings.TrimSuffix(version, "-aus"))
	} else {
		cpe = fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", util.Major(version))
	}

	pkgStats := []models.RedhatPackageState{}

	// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/index#cve_format
	err := r.conn.
		Not(map[string]interface{}{"fix_state": []string{"Not affected", "New"}}).
		Where(&models.RedhatPackageState{
			Cpe:         cpe,
			PackageName: pkgName,
		}).Find(&pkgStats).Error
	if err != nil {
		return nil, xerrors.Errorf("Failed to get unfixed cves of Redhat. err: %w", err)
	}

	redhatCVEIDs := map[int64]bool{}
	for _, p := range pkgStats {
		redhatCVEIDs[p.RedhatCVEID] = true
	}

	for id := range redhatCVEIDs {
		rhcve := models.RedhatCVE{}
		if err = r.conn.
			Preload("Bugzilla").
			Preload("Cvss").
			Preload("Cvss3").
			Preload("AffectedRelease").
			Preload("PackageState").
			Preload("Details").
			Preload("References").
			Where(&models.RedhatCVE{ID: id}).First(&rhcve).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, xerrors.Errorf("Failed to get RedhatCVE. DB relationship may be broken, use `$ gost fetch redhat` to recreate DB. err: %w", err)
			}
			return nil, xerrors.Errorf("Failed to get unfixed cves of Redhat. err: %w", err)
		}

		pkgStats := []models.RedhatPackageState{}
		for _, pkgstat := range rhcve.PackageState {
			if pkgstat.Cpe != cpe ||
				pkgstat.PackageName != pkgName ||
				pkgstat.FixState == "Not affected" ||
				pkgstat.FixState == "New" {
				continue

			} else if ignoreWillNotFix && pkgstat.FixState == "Will not fix" {
				continue
			}
			pkgStats = append(pkgStats, pkgstat)
		}
		if len(pkgStats) == 0 {
			continue
		}
		rhcve.PackageState = pkgStats
		m[rhcve.Name] = rhcve
	}
	return m, nil
}

// InsertRedhat :
func (r *RDBDriver) InsertRedhat(cves []models.RedhatCVE) (err error) {
	if err := r.deleteAndInsertRedhat(cves); err != nil {
		return xerrors.Errorf("Failed to insert RedHat CVE data. err: %w", err)
	}

	return nil
}

func (r *RDBDriver) deleteAndInsertRedhat(cves []models.RedhatCVE) (err error) {
	log15.Info(fmt.Sprintf("Insert %d CVEs", len(cves)))

	bar := pb.StartNew(len(cves))
	tx := r.conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatDetail{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatReference{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatBugzilla{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatCvss{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatCvss3{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatAffectedRelease{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatPackageState{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.RedhatCVE{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete . err: %w", err)
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
