package db

import (
	"strconv"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/knqyf263/gost/data"
	"github.com/knqyf263/gost/models"
)

// GetMicrosoft :
func (r *RDBDriver) GetMicrosoft(cveID string) *models.MicrosoftCVE {
	c := models.MicrosoftCVE{}
	//	err := r.conn.Where(&models.MicrosoftCVE{CveID: cveID}).First(&c).Error
	//	if err != nil && err != gorm.ErrRecordNotFound {
	//		log15.Error("Failed to get Microsoft", "err", err)
	//		return nil
	//	}
	//	err = r.conn.Model(&c).Related(&c.Package).Error
	//	if err != nil && err != gorm.ErrRecordNotFound {
	//		log15.Error("Failed to get Microsoft", "err", err)
	//		return nil
	//	}
	//
	//	var newPkg []models.MicrosoftPackage
	//	for _, pkg := range c.Package {
	//		err = r.conn.Model(&pkg).Related(&pkg.Release).Error
	//		if err != nil && err != gorm.ErrRecordNotFound {
	//			log15.Error("Failed to get Microsoft", "err", err)
	//			return nil
	//		}
	//		newPkg = append(newPkg, pkg)
	//	}
	//	c.Package = newPkg
	return &c
}

// InsertMicrosoft :
func (r *RDBDriver) InsertMicrosoft(cveJSON []models.MicrosoftXML) (err error) {
	//	cves := ConvertMicrosoft(cveJSON)
	//	if err = r.deleteAndInsertMicrosoft(r.conn, cves); err != nil {
	//		return fmt.Errorf("Failed to insert Microsoft CVE data. err: %s", err)
	//	}
	return nil
}

func (r *RDBDriver) deleteAndInsertMicrosoft(conn *gorm.DB, cves []models.MicrosoftCVE) (err error) {
	//	bar := pb.StartNew(len(cves))
	//	tx := conn.Begin()
	//
	//	defer func() {
	//		if err != nil {
	//			tx.Rollback()
	//			return
	//		}
	//		tx.Commit()
	//	}()
	//
	//	// Delete all old records
	//	var errs gorm.Errors
	//	errs = errs.Add(tx.Delete(models.MicrosoftRelease{}).Error)
	//	errs = errs.Add(tx.Delete(models.MicrosoftPackage{}).Error)
	//	errs = errs.Add(tx.Delete(models.MicrosoftCVE{}).Error)
	//	errs = util.DeleteNil(errs)
	//
	//	if len(errs.GetErrors()) > 0 {
	//		return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
	//	}
	//
	//	for _, cve := range cves {
	//		if err = tx.Create(&cve).Error; err != nil {
	//			return fmt.Errorf("Failed to insert. cve: %s, err: %s", cve.CveID, err)
	//		}
	//		bar.Increment()
	//	}
	//	bar.Finish()
	return nil
}

// ConvertMicrosoft :
func ConvertMicrosoft(cveXMLs []models.MicrosoftXML) (cves []models.MicrosoftCVE) {
	uniqCve := map[string]models.MicrosoftCVE{}
	// csv
	cveBulletinSearch := map[string][]data.BulletinSearch{}
	for _, b := range data.BulletinSearchs {
		cs := strings.Split(b.CVEs, ",")
		for _, c := range cs {
			cveBulletinSearch[c] = append(cveBulletinSearch[c], b)
		}
	}

	for cveID, bss := range cveBulletinSearch {
		uniqImpact := map[string]models.Threat{}
		uniqSeverity := map[string]models.Threat{}
		uniqKBIDs := map[string]bool{}
		var vendorFix []models.Remediation
		var title string
		var publishDate time.Time
		for _, bs := range bss {
			var productNames []string
			if len(bs.AffectedProduct) != 0 {
				productNames = append(productNames, bs.AffectedProduct)
			}
			if len(bs.AffectedComponent) != 0 {
				productNames = append(productNames, bs.AffectedComponent)
			}
			impact := models.Threat{
				Description:  bs.Impact,
				ProductNames: productNames,
			}
			if i, ok := uniqImpact[bs.Impact]; ok {
				impact.ProductNames = append(impact.ProductNames, i.ProductNames...)
			}
			uniqImpact[bs.Impact] = impact

			severity := models.Threat{
				Description:  bs.Severity,
				ProductNames: productNames,
			}
			if s, ok := uniqSeverity[bs.Severity]; ok {
				severity.ProductNames = append(severity.ProductNames, s.ProductNames...)
			}
			uniqSeverity[bs.Severity] = severity
			rem := models.Remediation{
				ProductNames:    productNames,
				RestartRequired: bs.Reboot,
				Supercedence:    bs.Supersedes,
			}
			vendorFix = append(vendorFix, rem)
			if len(bs.BulletinKB) != 0 {
				uniqKBIDs[bs.BulletinKB] = true
			}
			if len(bs.ComponentKB) != 0 {
				uniqKBIDs[bs.ComponentKB] = true
			}
			title = bs.Title
			var err error
			if publishDate, err = time.Parse("1/2/2006", bs.DatePosted); err != nil {
				if publishDate, err = time.Parse("1/2/06", bs.DatePosted); err != nil {
					log15.Warn("Failed to parse date", "date", bs.DatePosted)
				}
			}
		}

		var impact, severity []models.Threat
		var kbIDs []string
		for _, i := range uniqImpact {
			impact = append(impact, i)
		}
		for _, s := range uniqSeverity {
			severity = append(severity, s)
		}
		for k := range uniqKBIDs {
			kbIDs = append(kbIDs, k)
		}

		uniqCve[cveID] = models.MicrosoftCVE{
			Title:          title,
			CveID:          cveID,
			Impact:         impact,
			Severity:       severity,
			KBIDs:          kbIDs,
			PublishDate:    publishDate,
			LastUpdateDate: publishDate,
		}
	}

	// xml
	for _, cveXML := range cveXMLs {
		for _, vuln := range cveXML.Vulnerability {
			if len(vuln.CVE) == 0 {
				continue
			}
			var description, faq string
			for _, n := range vuln.Notes {
				switch n.AttrType {
				case "Description":
					description = n.Value
				case "FAQ":
					faq = n.Value
				case "Tag":
				case "General":
				case "Details":
				case "Summary":
				case "Legal Disclaimer":
				default:
					pp.Println("Notes", n.AttrType, n.AttrTitle)
				}
			}
			var productStatuses []models.MicrosoftProductStatus
			for _, p := range vuln.ProductStatuses {
				status := models.MicrosoftProductStatus{
					ProductIDs:    p.ProductID,
					ProductStatus: p.AttrType,
				}
				productStatuses = append(productStatuses, status)
			}
			var exploitStatus string
			uniqImpact := map[string]models.Threat{}
			uniqSeverity := map[string]models.Threat{}
			for _, t := range vuln.Threats {
				threat := models.Threat{
					Description: t.Description,
					ProductIDs:  t.ProductID,
				}
				switch t.AttrType {
				case "Impact":
					if th, ok := uniqImpact[t.Description]; ok {
						threat.ProductIDs = append(threat.ProductIDs, th.ProductIDs...)
					}
					uniqImpact[t.Description] = threat
				case "Severity":
					if th, ok := uniqSeverity[t.Description]; ok {
						threat.ProductIDs = append(threat.ProductIDs, th.ProductIDs...)

					}
					uniqSeverity[t.Description] = threat
				case "Exploit Status":
					exploitStatus = t.Description
				default:
					pp.Println("Threats", t.AttrType)
				}
			}

			var impact, severity []models.Threat
			for _, i := range uniqImpact {
				impact = append(impact, i)
			}
			for _, s := range uniqSeverity {
				severity = append(severity, s)
			}

			uniqScoreSets := map[string]models.ScoreSet{}
			for _, s := range vuln.CVSSScoreSets {
				scoreSet := models.ScoreSet{
					BaseScore:          s.BaseScore,
					TemporalScore:      s.TemporalScore,
					EnvironmentalScore: s.EnvironmentalScore,
					Vector:             s.Vector,
					ProductIDs:         s.ProductID,
				}
				if ss, ok := uniqScoreSets[s.Vector]; ok {
					scoreSet.ProductIDs = append(s.ProductID, ss.ProductIDs...)
				}
				uniqScoreSets[s.Vector] = scoreSet
			}

			var scoreSets []models.ScoreSet
			for _, scoreSet := range uniqScoreSets {
				scoreSets = append(scoreSets, scoreSet)
			}

			var mitigation, workaround string
			var vendorFix, noneAvailable, willNotFix []models.Remediation
			var kbIDs []string
			for _, r := range vuln.Remediations {
				remediation := models.Remediation{
					Description:     r.Description,
					ProductIDs:      r.ProductID,
					Entitlement:     r.Entitlement,
					RestartRequired: r.RestartRequired,
					SubType:         r.SubType,
					Supercedence:    r.Supercedence,
					URL:             r.URL,
				}
				switch r.AttrType {
				case "Workaround":
					workaround = r.Description
				case "Mitigation":
					mitigation = r.Description
				case "Vendor Fix":
					vendorFix = append(vendorFix, remediation)
					if _, err := strconv.Atoi(r.Description); err == nil {
						kbIDs = append(kbIDs, r.Description)
					}
				case "None Available":
					noneAvailable = append(noneAvailable, remediation)
				case "Will Not Fix":
					willNotFix = append(willNotFix, remediation)
				default:
					pp.Println("Remediations", r.AttrType)
				}
			}
			var references []models.MicrosoftReference
			for _, r := range vuln.References {
				ref := models.MicrosoftReference{
					AttrType:    r.AttrType,
					URL:         r.URL,
					Description: r.Description,
				}
				references = append(references, ref)
			}
			var lastUpdateDate, publishDate time.Time
			for _, t := range vuln.RevisionHistory {
				if t.Date.Time.After(lastUpdateDate) {
					lastUpdateDate = t.Date.Time
				}
				if publishDate.IsZero() || t.Date.Time.Before(publishDate) {
					publishDate = t.Date.Time
				}
			}

			uniqCve[vuln.CVE] = models.MicrosoftCVE{
				Title:       vuln.Title,
				Description: description,
				FAQ:         faq,
				CveID:       vuln.CVE,
				PublishDate: publishDate,
				CWE:         vuln.CWE,
				MicrosoftProductStatuses: productStatuses,
				Impact:         impact,
				Severity:       severity,
				ExploitStatus:  exploitStatus,
				Mitigation:     mitigation,
				Workaround:     workaround,
				VendorFix:      vendorFix,
				NoneAvailable:  noneAvailable,
				WillNotFix:     willNotFix,
				KBIDs:          kbIDs,
				References:     references,
				ScoreSets:      scoreSets,
				LastUpdateDate: lastUpdateDate,
			}
		}
	}

	for _, c := range uniqCve {
		cves = append(cves, c)
	}
	if len(uniqCve) != len(cves) {
		log15.Warn("Duplicate CVES", len(uniqCve), len(cves))
	}
	return cves
}

// GetUnfixedCvesMicrosoft :
func (r *RDBDriver) GetUnfixedCvesMicrosoft(major, pkgName string) map[string]models.MicrosoftCVE {
	m := map[string]models.MicrosoftCVE{}
	//	codeName, ok := debVerCodename[major]
	//	if !ok {
	//		log15.Error("Microsoft %s is not supported yet", "err", major)
	//		return m
	//	}
	//
	//	type Result struct {
	//		MicrosoftCveID int64
	//	}
	//	results := []Result{}
	//	err := r.conn.Table("debian_releases").
	//		Select("debian_cve_id").
	//		Joins("join debian_packages on debian_releases.debian_package_id = debian_packages.id AND debian_packages.package_name = ?", pkgName).
	//		Where(&models.MicrosoftRelease{
	//			ProductName: codeName,
	//			Status:      "open",
	//		}).Scan(&results).Error
	//
	//	if err != nil && err != gorm.ErrRecordNotFound {
	//		log15.Error("Failed to get unfixed cves of Microsoft", "err", err)
	//		return m
	//	}
	//
	//	for _, res := range results {
	//		debcve := models.MicrosoftCVE{}
	//		err = r.conn.
	//			Preload("Package").
	//			Where(&models.MicrosoftCVE{ID: res.MicrosoftCveID}).First(&debcve).Error
	//		if err != nil && err != gorm.ErrRecordNotFound {
	//			log15.Error("Failed to get MicrosoftCVE", res.MicrosoftCveID, err)
	//			return m
	//		}
	//
	//		pkgs := []models.MicrosoftPackage{}
	//		for _, pkg := range debcve.Package {
	//			if pkg.PackageName != pkgName {
	//				continue
	//			}
	//			err = r.conn.Model(&pkg).Related(&pkg.Release).Error
	//			if err != nil && err != gorm.ErrRecordNotFound {
	//				log15.Error("Failed to get MicrosoftRelease", pkg.Release, err)
	//				return m
	//			}
	//
	//			rels := []models.MicrosoftRelease{}
	//			for _, rel := range pkg.Release {
	//				if rel.ProductName == codeName && rel.Status == "open" {
	//					rels = append(rels, rel)
	//				}
	//			}
	//			if len(rels) == 0 {
	//				continue
	//			}
	//			pkg.Release = rels
	//			pkgs = append(pkgs, pkg)
	//		}
	//		if len(pkgs) != 0 {
	//			debcve.Package = pkgs
	//			m[debcve.CveID] = debcve
	//		}
	//	}
	return m
}
