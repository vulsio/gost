package db

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	strip "github.com/grokify/html-strip-tags-go"
	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
)

// GetMicrosoft :
func (r *RDBDriver) GetMicrosoft(cveID string) *models.MicrosoftCVE {
	c := models.MicrosoftCVE{}

	var errs gorm.Errors
	errs = errs.Add(r.conn.Where(&models.RedhatCVE{Name: cveID}).First(&c).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.MicrosoftProductStatuses).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Impact).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.Severity).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.VendorFix).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.NoneAvailable).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.WillNotFix).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.References).Error)
	errs = errs.Add(r.conn.Model(&c).Related(&c.ScoreSets).Error)
	errs = util.DeleteRecordNotFound(errs)
	if len(errs.GetErrors()) > 0 {
		log15.Error("Failed to delete old records", "err", errs.Error())
	}
	return &c
}

// GetMicrosoftMulti :
func (r *RDBDriver) GetMicrosoftMulti(cveIDs []string) map[string]models.MicrosoftCVE {
	m := map[string]models.MicrosoftCVE{}
	for _, cveID := range cveIDs {
		m[cveID] = *r.GetMicrosoft(cveID)
	}
	return m
}

// InsertMicrosoft :
func (r *RDBDriver) InsertMicrosoft(cveJSON []models.MicrosoftXML, cveXls []models.MicrosoftBulletinSearch) (err error) {
	cves, _ := ConvertMicrosoft(cveJSON, cveXls)
	if err = r.deleteAndInsertMicrosoft(r.conn, cves); err != nil {
		return fmt.Errorf("Failed to insert Microsoft CVE data. err: %s", err)
	}
	return nil
}

func (r *RDBDriver) deleteAndInsertMicrosoft(conn *gorm.DB, cves []models.MicrosoftCVE) (err error) {
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
	errs = errs.Add(tx.Delete(models.MicrosoftScoreSet{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftReference{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftKBID{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftRemediation{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftThreat{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftProductStatus{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftProduct{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftScoreSet{}).Error)
	errs = errs.Add(tx.Delete(models.MicrosoftCVE{}).Error)
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

// ConvertMicrosoft :
func ConvertMicrosoft(cveXMLs []models.MicrosoftXML, cveXls []models.MicrosoftBulletinSearch) (cves []models.MicrosoftCVE, msProducts []models.MicrosoftProduct) {
	uniqCve := map[string]models.MicrosoftCVE{}
	uniqProduct := map[string]string{}

	// xml
	for _, cveXML := range cveXMLs {
		ptree := cveXML.ProductTree
		if ptree != nil {
			for _, p := range ptree.FullProductName {
				uniqProduct[p.AttrProductID] = p.Value
			}
			if ptree.Branch != nil {
				for _, p := range ptree.Branch.FullProductName {
					uniqProduct[p.AttrProductID] = p.Value
				}
			}
		}
		for _, vuln := range cveXML.Vulnerability {
			if len(vuln.CVE) == 0 {
				continue
			}
			var description, faq string
			for _, n := range vuln.Notes {
				switch n.AttrType {
				case "Description":
					description = strip.StripTags(n.Value)
				case "FAQ":
					faq = n.Value
				case "Tag":
				case "General":
				case "Details":
				case "Summary":
				case "Legal Disclaimer":
				default:
					log15.Info("New Notes", "Type", n.AttrType, "Title", n.AttrTitle)
				}
			}
			var productStatuses []models.MicrosoftProductStatus
			for _, p := range vuln.ProductStatuses {
				var products []models.MicrosoftProduct
				for _, productID := range p.ProductID {
					product := models.MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				status := models.MicrosoftProductStatus{
					Products:      products,
					ProductStatus: p.AttrType,
				}
				productStatuses = append(productStatuses, status)
			}
			var exploitStatus string
			uniqImpact := map[string]models.MicrosoftThreat{}
			uniqSeverity := map[string]models.MicrosoftThreat{}
			for _, t := range vuln.Threats {
				var products []models.MicrosoftProduct
				for _, productID := range t.ProductID {
					product := models.MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				threat := models.MicrosoftThreat{
					Description: t.Description,
					Products:    products,
				}
				switch t.AttrType {
				case "Impact":
					if th, ok := uniqImpact[t.Description]; ok {
						threat.Products = append(threat.Products, th.Products...)
					}
					uniqImpact[t.Description] = threat
				case "Severity":
					if th, ok := uniqSeverity[t.Description]; ok {
						threat.Products = append(threat.Products, th.Products...)

					}
					uniqSeverity[t.Description] = threat
				case "Exploit Status":
					exploitStatus = t.Description
				default:
					log15.Info("New Threats", "Type", t.AttrType)
				}
			}

			var impact, severity []models.MicrosoftThreat
			for _, i := range uniqImpact {
				impact = append(impact, i)
			}
			for _, s := range uniqSeverity {
				severity = append(severity, s)
			}

			uniqScoreSets := map[string]models.MicrosoftScoreSet{}
			for _, s := range vuln.CVSSScoreSets {
				var products []models.MicrosoftProduct
				for _, productID := range s.ProductID {
					product := models.MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				scoreSet := models.MicrosoftScoreSet{
					BaseScore:          s.BaseScore,
					TemporalScore:      s.TemporalScore,
					EnvironmentalScore: s.EnvironmentalScore,
					Vector:             s.Vector,
					Products:           products,
				}
				if ss, ok := uniqScoreSets[s.Vector]; ok {
					scoreSet.Products = append(scoreSet.Products, ss.Products...)
				}
				uniqScoreSets[s.Vector] = scoreSet
			}

			var scoreSets []models.MicrosoftScoreSet
			for _, scoreSet := range uniqScoreSets {
				scoreSets = append(scoreSets, scoreSet)
			}

			var mitigation, workaround string
			var vendorFix, noneAvailable, willNotFix []models.MicrosoftRemediation
			uniqKBIDs := map[string]bool{}
			for _, r := range vuln.Remediations {
				var products []models.MicrosoftProduct
				for _, productID := range r.ProductID {
					product := models.MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				remediation := models.MicrosoftRemediation{
					Description:     r.Description,
					Products:        products,
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
						uniqKBIDs[r.Description] = true
					}
				case "None Available":
					noneAvailable = append(noneAvailable, remediation)
				case "Will Not Fix":
					willNotFix = append(willNotFix, remediation)
				default:
					log15.Info("New Remediations", "Type", r.AttrType)
				}
			}

			var kbIDs []models.MicrosoftKBID
			for kbID := range uniqKBIDs {
				kbIDs = append(kbIDs, models.MicrosoftKBID{KBID: kbID})
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
				Title:                    vuln.Title,
				Description:              description,
				FAQ:                      faq,
				CveID:                    vuln.CVE,
				PublishDate:              publishDate,
				CWE:                      vuln.CWE,
				MicrosoftProductStatuses: productStatuses,
				Impact:                   impact,
				Severity:                 severity,
				ExploitStatus:            exploitStatus,
				Mitigation:               mitigation,
				Workaround:               workaround,
				VendorFix:                vendorFix,
				NoneAvailable:            noneAvailable,
				WillNotFix:               willNotFix,
				KBIDs:                    kbIDs,
				References:               references,
				ScoreSets:                scoreSets,
				LastUpdateDate:           lastUpdateDate,
			}
		}
	}

	for id, name := range uniqProduct {
		msProduct := models.MicrosoftProduct{
			ProductID:   id,
			ProductName: name,
		}
		msProducts = append(msProducts, msProduct)
	}

	// csv
	cveBulletinSearch := map[string][]models.MicrosoftBulletinSearch{}
	for _, b := range cveXls {
		cs := strings.Split(b.CVEs, ",")
		for _, c := range cs {
			cveBulletinSearch[c] = append(cveBulletinSearch[c], b)
		}
	}

	for cveID, bss := range cveBulletinSearch {
		if len(cveID) == 0 {
			continue
		}
		uniqImpact := map[string]models.MicrosoftThreat{}
		uniqSeverity := map[string]models.MicrosoftThreat{}
		uniqKBIDs := map[string]bool{}
		var vendorFix []models.MicrosoftRemediation
		var title string
		var publishDate time.Time
		for _, bs := range bss {
			var products []models.MicrosoftProduct
			if len(bs.AffectedProduct) != 0 {
				product := getProductFromName(msProducts, bs.AffectedProduct)
				products = append(products, product)
			}
			if len(bs.AffectedComponent) != 0 {
				product := getProductFromName(msProducts, bs.AffectedComponent)
				products = append(products, product)
			}
			impact := models.MicrosoftThreat{
				Description: bs.Impact,
				Products:    products,
			}
			if i, ok := uniqImpact[bs.Impact]; ok {
				impact.Products = append(impact.Products, i.Products...)
			}
			uniqImpact[bs.Impact] = impact

			severity := models.MicrosoftThreat{
				Description: bs.Severity,
				Products:    products,
			}
			if s, ok := uniqSeverity[bs.Severity]; ok {
				severity.Products = append(severity.Products, s.Products...)
			}
			uniqSeverity[bs.Severity] = severity
			rem := models.MicrosoftRemediation{
				Products:        products,
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
				if publishDate, err = time.Parse("1-2-06", bs.DatePosted); err != nil {
					log15.Warn("Failed to parse date", "date", bs.DatePosted)
				}
			}
		}

		var impact, severity []models.MicrosoftThreat
		var kbIDs []models.MicrosoftKBID
		for _, i := range uniqImpact {
			impact = append(impact, i)
		}
		for _, s := range uniqSeverity {
			severity = append(severity, s)
		}
		for k := range uniqKBIDs {
			kbID := models.MicrosoftKBID{
				KBID: k,
			}
			kbIDs = append(kbIDs, kbID)
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

	for _, c := range uniqCve {
		cves = append(cves, c)
	}
	if len(uniqCve) != len(cves) {
		log15.Warn("Duplicate CVES", len(uniqCve), len(cves))
	}
	return cves, msProducts
}

func getProductFromName(msProducts []models.MicrosoftProduct, productName string) models.MicrosoftProduct {
	for _, msp := range msProducts {
		if productName == msp.ProductName {
			return msp
		}
	}
	return models.MicrosoftProduct{
		ProductName: productName,
	}
}

// GetUnfixedCvesMicrosoft :
func (r *RDBDriver) GetUnfixedCvesMicrosoft(major, pkgName string, detectWillNotFix ...bool) map[string]models.MicrosoftCVE {
	m := map[string]models.MicrosoftCVE{}
	return m
}
