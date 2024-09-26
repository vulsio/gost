package db

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/models"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
)

// GetArch :
func (r *RDBDriver) GetArch(advID string) (*models.ArchADV, error) {
	var a models.ArchADV
	if err := r.conn.
		Preload("Packages").
		Preload("Issues").
		Preload("Advisories").
		Where(&models.ArchADV{Name: advID}).
		First(&a).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, xerrors.Errorf("Failed to find first record by %s. err: %w", advID, err)
	}
	return &a, nil
}

// GetArchMulti :
func (r *RDBDriver) GetArchMulti(advIDs []string) (map[string]models.ArchADV, error) {
	m := make(map[string]models.ArchADV)
	for _, id := range advIDs {
		a, err := r.GetArch(id)
		if err != nil {
			return nil, xerrors.Errorf("Failed to get Arch. err: %w", err)
		}
		if a != nil {
			m[id] = *a
		}
	}
	return m, nil
}

// InsertArch :
func (r *RDBDriver) InsertArch(advs []models.ArchADV) error {
	if err := r.deleteAndInsertArch(advs); err != nil {
		return xerrors.Errorf("Failed to insert Arch Advisory data. err: %w", err)
	}
	return nil
}

func (r *RDBDriver) deleteAndInsertArch(advs []models.ArchADV) (err error) {
	bar := pb.StartNew(len(advs)).SetWriter(func() io.Writer {
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
	for _, table := range []interface{}{models.ArchAdvisory{}, models.ArchIssue{}, models.ArchPackage{}, models.ArchADV{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for chunk := range slices.Chunk(advs, batchSize) {
		if err = tx.Create(chunk).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(len(chunk))
	}
	bar.Finish()

	return nil
}

// GetUnfixedAdvsArch :
func (r *RDBDriver) GetUnfixedAdvsArch(pkgName string) (map[string]models.ArchADV, error) {
	return r.getAdvsArchWithFixStatus(pkgName, "Vulnerable")
}

// GetFixedAdvsArch :
func (r *RDBDriver) GetFixedAdvsArch(pkgName string) (map[string]models.ArchADV, error) {
	return r.getAdvsArchWithFixStatus(pkgName, "Fixed")
}

func (r *RDBDriver) getAdvsArchWithFixStatus(pkgName, fixStatus string) (map[string]models.ArchADV, error) {
	var as []models.ArchADV
	if err := r.conn.
		Joins("JOIN arch_packages ON arch_packages.arch_adv_id = arch_advs.id AND arch_packages.name = ?", pkgName).
		Preload("Packages").
		Preload("Issues").
		Preload("Advisories").
		Where(&models.ArchADV{Status: fixStatus}).
		Find(&as).Error; err != nil {
		return nil, xerrors.Errorf("Failed to find advisory by pkgname: %s, fix status: %s. err: %w", pkgName, fixStatus, err)
	}

	m := make(map[string]models.ArchADV)
	for _, a := range as {
		m[a.Name] = a
	}
	return m, nil
}

// GetAdvisoriesArch gets AdvisoryID: []CVE IDs
func (r *RDBDriver) GetAdvisoriesArch() (map[string][]string, error) {
	m := make(map[string][]string)
	var as []models.ArchADV
	// the maximum value of a host parameter number is SQLITE_MAX_VARIABLE_NUMBER, which defaults to 999 for SQLite versions prior to 3.32.0 (2020-05-22) or 32766 for SQLite versions after 3.32.0.
	// https://www.sqlite.org/limits.html Maximum Number Of Host Parameters In A Single SQL Statement
	if err := r.conn.Preload("Issues").FindInBatches(&as, 999, func(_ *gorm.DB, _ int) error {
		for _, a := range as {
			for _, i := range a.Issues {
				m[a.Name] = append(m[a.Name], i.Issue)
			}
		}
		return nil
	}).Error; err != nil {
		return nil, xerrors.Errorf("Failed to find Arch. err: %w", err)
	}

	return m, nil
}
