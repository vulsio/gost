package db

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	strip "github.com/grokify/html-strip-tags-go"
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	"gorm.io/gorm"
)

// GetMicrosoft :
func (r *RDBDriver) GetMicrosoft(cveID string) *models.MicrosoftCVE {
	c := models.MicrosoftCVE{}
	var errs util.Errors
	errs = errs.Add(r.conn.Where(&models.MicrosoftCVE{CveID: cveID}).First(&c).Error)
	log15.Debug("microsoft_cve_id", "ID", c.ID)

	errs = errs.Add(r.conn.Model(&c).Association("MicrosoftProductStatuses").Find(&c.MicrosoftProductStatuses))
	if len(c.MicrosoftProductStatuses) == 0 {
		c.MicrosoftProductStatuses = nil
	} else {
		for i := range c.MicrosoftProductStatuses {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("MicrosoftProductStatus:%d", i)).Find(&c.MicrosoftProductStatuses[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Impact'", c.ID).Find(&c.Impact).Error)
	if len(c.Impact) == 0 {
		c.Impact = nil
	} else {
		for i := range c.Impact {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("Impact:%d", i)).Find(&c.Impact[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Severity'", c.ID).Find(&c.Severity).Error)
	if len(c.Severity) == 0 {
		c.Severity = nil
	} else {
		for i := range c.Severity {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("Severity:%d", i)).Find(&c.Severity[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Vendor Fix'", c.ID).Find(&c.VendorFix).Error)
	if len(c.VendorFix) == 0 {
		c.VendorFix = nil
	} else {
		for i := range c.VendorFix {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("VendorFix:%d", i)).Find(&c.VendorFix[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND attr_type = 'None Available'", c.ID).Find(&c.NoneAvailable).Error)
	if len(c.NoneAvailable) == 0 {
		c.NoneAvailable = nil
	} else {
		for i := range c.NoneAvailable {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("NoneAvailable:%d", i)).Find(&c.NoneAvailable[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Will Not Fix'", c.ID).Find(&c.WillNotFix).Error)
	if len(c.WillNotFix) == 0 {
		c.WillNotFix = nil
	} else {
		for i := range c.WillNotFix {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("WillNotFix:%d", i)).Find(&c.WillNotFix[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Model(&c).Association("ScoreSets").Find(&c.ScoreSets))
	if len(c.ScoreSets) == 0 {
		c.ScoreSets = nil
	} else {
		for i := range c.ScoreSets {
			errs = errs.Add(r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("MicrosoftScoreSet:%d", i)).Find(&c.ScoreSets[i].Products).Error)
		}
	}

	errs = errs.Add(r.conn.Model(&c).Association("References").Find(&c.References))
	if len(c.References) == 0 {
		c.References = nil
	}

	errs = errs.Add(r.conn.Model(&c).Association("KBIDs").Find(&c.KBIDs))
	if len(c.KBIDs) == 0 {
		c.KBIDs = nil
	}

	errs = util.DeleteRecordNotFound(errs)
	if len(errs.GetErrors()) > 0 {
		log15.Error("Failed to find records", "err", errs.Error())
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
	var errs util.Errors
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftScoreSet{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftReference{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftKBID{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftRemediation{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftThreat{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftProductStatus{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftProduct{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftScoreSet{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftCVE{}).Error)
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
				case "CNA":
				default:
					log15.Info("New Notes", "Type", n.AttrType, "Title", n.AttrTitle)
				}
			}

			var productStatuses []models.MicrosoftProductStatus
			for i, p := range vuln.ProductStatuses {
				var products []models.MicrosoftProduct
				for _, productID := range p.ProductID {
					product := models.MicrosoftProduct{
						Category:    fmt.Sprintf("MicrosoftProductStatus:%d", i),
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
						Category:    "MicrosoftThreat",
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				threat := models.MicrosoftThreat{
					Description: t.Description,
					Products:    products,
					AttrType:    t.AttrType,
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
			index := 0
			for _, i := range uniqImpact {
				for j := range i.Products {
					i.Products[j].Category = fmt.Sprintf("Impact:%d", index)
				}
				impact = append(impact, i)
				index = index + 1
			}

			index = 0
			for _, s := range uniqSeverity {
				for j := range s.Products {
					s.Products[j].Category = fmt.Sprintf("Severity:%d", index)
				}
				severity = append(severity, s)
				index = index + 1
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
			index = 0
			for _, scoreSet := range uniqScoreSets {
				for j := range scoreSet.Products {
					scoreSet.Products[j].Category = fmt.Sprintf("MicrosoftScoreSet:%d", index)
				}
				scoreSets = append(scoreSets, scoreSet)
				index = index + 1
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
					AttrType:        r.AttrType,
				}
				switch r.AttrType {
				case "Workaround":
					workaround = r.Description
				case "Mitigation":
					mitigation = r.Description
				case "Vendor Fix":
					for j := range remediation.Products {
						remediation.Products[j].Category = fmt.Sprintf("VendorFix:%d", len(vendorFix))
					}
					vendorFix = append(vendorFix, remediation)
					if _, err := strconv.Atoi(r.Description); err == nil {
						uniqKBIDs[r.Description] = true
					}
				case "None Available":
					for j := range remediation.Products {
						remediation.Products[j].Category = fmt.Sprintf("NoneAvailable:%d", len(noneAvailable))
					}
					noneAvailable = append(noneAvailable, remediation)
				case "Will Not Fix":
					for j := range remediation.Products {
						remediation.Products[j].Category = fmt.Sprintf("WillNotFix:%d", len(willNotFix))
					}
					willNotFix = append(willNotFix, remediation)
				default:
					log15.Debug("New Remediation", "Type", r)
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

	sort.Slice(msProducts, func(i, j int) bool {
		return msProducts[i].ProductID < msProducts[j].ProductID
	})

	// csv
	cveBulletinSearch := map[string][]models.MicrosoftBulletinSearch{}
	for _, b := range cveXls {
		if b.CVEs == "" {
			continue
		}
		cs := strings.Split(strings.ToUpper(strings.ReplaceAll(strings.TrimSuffix(b.CVEs, "\n"), " ", "")), ",")
		for _, c := range cs {
			// c: CVE-2021-31936, CAN-2001-0002, CVE-2015-2442CVE-2015-2446, CVE-CVE-2007-0515, CVE, CVE2007-0029, CVE20163325, 2008-1438
			log15.Debug("parse string containing CVE-ID", "c", c)
			if strings.HasPrefix(c, "CVE-") {
				// c: CVE-2021-31936, CVE-2015-2442CVE-2015-2446, CVE-CVE-2007-0515
				ss := strings.Split(c, "CVE-")
				for _, cveNumber := range ss {
					if cveNumber == "" {
						continue
					}
					cveID := fmt.Sprintf("CVE-%s", cveNumber)
					cveBulletinSearch[cveID] = append(cveBulletinSearch[cveID], b)
				}
			} else {
				// c: CAN-2001-0002, CVE20163325, 2008-1438
				if strings.HasPrefix(c, "CAN-") {
					cveBulletinSearch[c] = append(cveBulletinSearch[c], b)
				} else {
					// c: CVE, CVE2007-0029, CVE20163325, 2008-1438
					var cveID string
					if strings.HasPrefix(c, "CVE") {
						// c: CVE, CVE2007-0029, CVE20163325
						cveNumber := strings.TrimPrefix(c, "CVE")
						if cveNumber == "" {
							continue
						}
						if strings.Contains(cveNumber, "-") {
							// cveNumber: 2007-0029
							cveID = fmt.Sprintf("CVE-%s", cveNumber)
						} else {
							// cveNumber: 20163325
							if len(cveNumber) < 8 {
								continue
							}
							cveID = fmt.Sprintf("CVE-%s-%s", c[3:7], c[7:])
						}
					} else {
						// c: 2008-1438
						cveID = fmt.Sprintf("CVE-%s", c)
					}
					cveBulletinSearch[cveID] = append(cveBulletinSearch[cveID], b)
				}
			}
		}
	}

	for cveID, bss := range cveBulletinSearch {
		if _, ok := uniqCve[cveID]; ok {
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
				Products:    append([]models.MicrosoftProduct(nil), products...),
				AttrType:    "Impact",
			}
			if i, ok := uniqImpact[bs.Impact]; ok {
				impact.Products = append(impact.Products, i.Products...)
			}
			uniqImpact[bs.Impact] = impact

			severity := models.MicrosoftThreat{
				Description: bs.Severity,
				Products:    append([]models.MicrosoftProduct(nil), products...),
				AttrType:    "Severity",
			}
			if s, ok := uniqSeverity[bs.Severity]; ok {
				severity.Products = append(severity.Products, s.Products...)
			}
			uniqSeverity[bs.Severity] = severity

			rem := models.MicrosoftRemediation{
				Products:        append([]models.MicrosoftProduct(nil), products...),
				RestartRequired: bs.Reboot,
				Supercedence:    bs.Supersedes,
				AttrType:        "Vendor Fix",
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
		index := 0
		for _, i := range uniqImpact {
			for j := range i.Products {
				i.Products[j].Category = fmt.Sprintf("Impact:%d", index)
			}
			impact = append(impact, i)
			index = index + 1
		}

		index = 0
		for _, s := range uniqSeverity {
			for j := range s.Products {
				s.Products[j].Category = fmt.Sprintf("Severity:%d", index)
			}
			severity = append(severity, s)
			index = index + 1
		}

		for i := range vendorFix {
			for j := range vendorFix[i].Products {
				vendorFix[i].Products[j].Category = fmt.Sprintf("VendorFix:%d", i)
			}
		}

		for k := range uniqKBIDs {
			kbID := models.MicrosoftKBID{
				KBID: k,
			}
			kbIDs = append(kbIDs, kbID)
		}

		uniqCve[cveID] = models.MicrosoftCVE{
			Title:    title,
			CveID:    cveID,
			Impact:   impact,
			Severity: severity,
			// VendorFix:      vendorFix,
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
