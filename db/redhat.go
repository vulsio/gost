package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/knqyf263/go-security-tracker/models"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func (r *RDBDriver) GetRedhat(cveID string) *models.RedhatCVE {
	c := models.RedhatCVE{}
	r.conn.Where(&models.RedhatCVE{Name: cveID}).First(&c)
	r.conn.Model(&c).Related(&c.Details).Related(&c.References).Related(&c.Bugzilla).Related(&c.Cvss)
	r.conn.Model(&c).Related(&c.Cvss3).Related(&c.AffectedRelease).Related(&c.PackageState)
	return &c
}

func (r *RDBDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	cves := convertRedhat(cveJSONs)
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		if err := deleteAndInsertRedhat(r.conn, cve); err != nil {
			return fmt.Errorf("Failed to insert. cve: %s, err: %s",
				cve.Name, err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func deleteAndInsertRedhat(conn *gorm.DB, cve models.RedhatCVE) (err error) {
	tx := conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete old records if found
	old := models.RedhatCVE{}
	result := tx.Where(&models.RedhatCVE{Name: cve.Name}).First(&old)
	if !result.RecordNotFound() {
		cve.ID = old.ID

		// Delete old records
		var errs gorm.Errors
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatDetail{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatReference{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatBugzilla{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatCvss{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatCvss3{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatAffectedRelease{}).Error)
		errs = errs.Add(tx.Where("redhat_cve_id = ?", old.ID).Delete(models.RedhatPackageState{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(&old).Error)

		// Delete nil in errs
		var new []error
		for _, err := range errs {
			if err != nil {
				new = append(new, err)
			}
		}
		errs = new

		if len(errs.GetErrors()) > 0 {
			return fmt.Errorf("Failed to delete old records. cve: %s, err: %s",
				cve.Name, errs.Error())
		}
	}
	if err = tx.Create(&cve).Error; err != nil {
		return err
	}
	return nil
}

func convertRedhat(cveJSONs []models.RedhatCVEJSON) (cves []models.RedhatCVE) {
	for _, cve := range cveJSONs {
		var details []models.RedhatDetail
		for _, d := range cve.Details {
			details = append(details, models.RedhatDetail{Detail: d})
		}

		var references []models.RedhatReference
		for _, r := range cve.References {
			references = append(references, models.RedhatReference{Reference: r})
		}

		// TODO: more efficient
		c := models.RedhatCVE{
			ThreatSeverity:       cve.ThreatSeverity,
			PublicDate:           cve.PublicDate,
			Bugzilla:             cve.Bugzilla,
			Cvss:                 cve.Cvss,
			Cvss3:                cve.Cvss3,
			Iava:                 cve.Iava,
			Cwe:                  cve.Cwe,
			Statement:            cve.Statement,
			Acknowledgement:      cve.Acknowledgement,
			Mitigation:           cve.Mitigation,
			AffectedRelease:      cve.AffectedRelease,
			PackageState:         cve.PackageState,
			Name:                 cve.Name,
			DocumentDistribution: cve.DocumentDistribution,

			Details:    details,
			References: references,
		}
		cves = append(cves, c)
	}
	return cves
}
