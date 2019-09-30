package db

import (
	"strings"
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func (r *RDBDriver) GetAfterTimeRedhat(after time.Time) (allCves []models.RedhatCVE, err error) {
	all := []models.RedhatCVE{}
	if err = r.conn.Where("public_date >= ?", after.Format("2006-01-02")).Find(&all).Error; err != nil {
		return nil, err
	}

	// TODO: insufficient
	for _, a := range all {
		r.conn.Model(&a).Related(&a.Cvss3).Related(&a.Details).Related(&a.PackageState)
		allCves = append(allCves, a)
	}
	return allCves, nil
}

func (r *RDBDriver) GetRedhat(cveID string) *models.RedhatCVE {
	c := models.RedhatCVE{}
	var errs gorm.Errors
	errs = errs.Add(r.conn.Where(&models.RedhatCVE{Name: cveID}).First(&c).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Details).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.References).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Bugzilla).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Cvss).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Cvss3).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.AffectedRelease).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.PackageState).Error)
	errs = util.DeleteRecordNotFound(errs)
	if len(errs.GetErrors()) > 0 {
		log15.Error("Failed to delete old records", "err", errs.Error())
	}
	return &c
}

func (r *RDBDriver) GetRedhatMulti(cveIDs []string) map[string]models.RedhatCVE {
	m := map[string]models.RedhatCVE{}
	for _, cveID := range cveIDs {
		m[cveID] = *r.GetRedhat(cveID)
	}
	return m
}

func (r *RDBDriver) GetUnfixedCvesRedhat(major, pkgName string, ignoreWillNotFix bool) map[string]models.RedhatCVE {
	m := map[string]models.RedhatCVE{}
	cpe := fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", major)
	pkgStats := []models.RedhatPackageState{}

	// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/index#cve_format
	err := r.conn.
		Not("fix_state", []string{"Not affected", "New"}).
		Where(&models.RedhatPackageState{
			Cpe:         cpe,
			PackageName: pkgName,
		}).Find(&pkgStats).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		log15.Error("Failed to get unfixed cves of Redhat", "err", err)
		return nil
	}

	redhatCVEIDs := map[int64]bool{}
	for _, p := range pkgStats {
		redhatCVEIDs[p.RedhatCVEID] = true
	}

	for id := range redhatCVEIDs {
		rhcve := models.RedhatCVE{}
		err = r.conn.
			Preload("Bugzilla").
			Preload("Cvss").
			Preload("Cvss3").
			Preload("AffectedRelease").
			Preload("PackageState").
			Preload("Details").
			Preload("References").
			Where(&models.RedhatCVE{ID: id}).First(&rhcve).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			log15.Error("Failed to get unfixed cves of Redhat", "err", err)
			return nil
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
	return m
}

func (r *RDBDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	cves, err := ConvertRedhat(cveJSONs)
	if err != nil {
		return err
	}

	bar := pb.StartNew(len(cves))

	log15.Info(fmt.Sprintf("Insert %d CVEs", len(cves)))
	for _, cve := range cves {
		if err := r.deleteAndInsertRedhat(r.conn, cve); err != nil {
			return fmt.Errorf("Failed to insert. cve: %s, err: %s",
				cve.Name, err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (r *RDBDriver) deleteAndInsertRedhat(conn *gorm.DB, cve models.RedhatCVE) (err error) {
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

func ConvertRedhat(cveJSONs []models.RedhatCVEJSON) (cves []models.RedhatCVE, err error) {
	for _, cve := range cveJSONs {
		var details []models.RedhatDetail
		for _, d := range cve.Details {
			d = util.TrimSpaceNewline(d)
			details = append(details, models.RedhatDetail{Detail: d})
		}

		var references []models.RedhatReference
		for _, r := range cve.References {
			r = util.TrimSpaceNewline(r)
			references = append(references, models.RedhatReference{Reference: r})
		}

		cve.Bugzilla.Description = util.TrimSpaceNewline(cve.Bugzilla.Description)
		cve.Statement = util.TrimSpaceNewline(cve.Statement)

		var publicDate time.Time
		if cve.PublicDate != "" {
			if strings.HasSuffix(cve.PublicDate, "Z") {
				publicDate, err = time.Parse("2006-01-02T15:04:05Z", cve.PublicDate)
			}else {
				publicDate, err = time.Parse("2006-01-02T15:04:05", cve.PublicDate)
			}
			if err != nil {
				return nil, fmt.Errorf("Failed to parse date. date: %s err: %s", cve.PublicDate, err)
			}
		}

		// TODO: more efficient
		c := models.RedhatCVE{
			ThreatSeverity:       cve.ThreatSeverity,
			PublicDate:           publicDate,
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
	return cves, nil
}

func ClearIDRedhat(cve *models.RedhatCVE) {
	cve.ID = 0
	cve.Bugzilla.RedhatCVEID = 0
	cve.Cvss.RedhatCVEID = 0
	cve.Cvss3.RedhatCVEID = 0

	affectedReleases := cve.AffectedRelease
	cve.AffectedRelease = []models.RedhatAffectedRelease{}
	for _, a := range affectedReleases {
		a.RedhatCVEID = 0
		cve.AffectedRelease = append(cve.AffectedRelease, a)
	}

	packageState := cve.PackageState
	cve.PackageState = []models.RedhatPackageState{}
	for _, p := range packageState {
		p.RedhatCVEID = 0
		cve.PackageState = append(cve.PackageState, p)
	}

	details := cve.Details
	cve.Details = []models.RedhatDetail{}
	for _, d := range details {
		d.RedhatCVEID = 0
		cve.Details = append(cve.Details, d)
	}

	references := cve.References
	cve.References = []models.RedhatReference{}
	for _, r := range references {
		r.RedhatCVEID = 0
		cve.References = append(cve.References, r)
	}

}
