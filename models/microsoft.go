package models

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	strip "github.com/grokify/html-strip-tags-go"
	"github.com/inconshreveable/log15"
)

// Updatelist :
type Updatelist struct {
	Value []struct {
		ID                 string    `json:"ID"`
		Alias              string    `json:"Alias"`
		DocumentTitle      string    `json:"DocumentTitle"`
		Severity           string    `json:"Severity"`
		InitialReleaseDate time.Time `json:"InitialReleaseDate"`
		CurrentReleaseDate time.Time `json:"CurrentReleaseDate"`
		CvrfURL            string    `json:"CvrfUrl"`
	} `json:"value"`
}

// MicrosoftXML :
// http://www.icasi.org/cvrf-v1-1-dictionary-of-elements/
type MicrosoftXML struct {
	XMLName             xml.Name `xml:"cvrfdoc"`
	AttrXmlnsCpeLang    string   `xml:"xmlns cpe-lang,attr"`
	AttrXmlnsCvrf       string   `xml:"xmlns cvrf,attr"`
	AttrXmlnsCvrfCommon string   `xml:"xmlns cvrf-common,attr"`
	AttrXmlnsCvssv2     string   `xml:"xmlns cvssv2,attr"`
	AttrXmlnsDc         string   `xml:"xmlns dc,attr"`
	AttrXmlnsProd       string   `xml:"xmlns prod,attr"`
	AttrXmlnsScapCore   string   `xml:"xmlns scap-core,attr"`
	AttrXmlnsSch        string   `xml:"xmlns sch,attr"`
	AttrXmlnsVuln       string   `xml:"xmlns vuln,attr"`
	DocumentTitle       string   `xml:"DocumentTitle"`
	DocumentType        string   `xml:"DocumentType"`
	DocumentPublisher   *struct {
		AttrType         string `xml:"Type,attr"`
		ContactDetails   string `xml:"ContactDetails"`
		IssuingAuthority string `xml:"IssuingAuthority"`
	} `xml:"DocumentPublisher"`
	DocumentTracking *struct {
		ID    string `xml:"Identification>ID"`
		Alias string `xml:"Identification>Alias"`
		// Draft, Interim, Final
		Status string `xml:"Status"`
		// (0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,3}.
		Version         string `xml:"Version"`
		RevisionHistory []struct {
			Number      float64 `xml:"Number"`
			Date        Mstime  `xml:"Date"`
			Description string  `xml:"Description"`
		} `xml:"RevisionHistory>Revision"`
		InitialReleaseDate Mstime `xml:"InitialReleaseDate"`
		CurrentReleaseDate Mstime `xml:"CurrentReleaseDate"`
		Generator          struct {
			Engine string `xml:"Engine"`
			Date   Mstime `xml:"Date"`
		} `xml:"Generator"`
	} `xml:"DocumentTracking"`
	DocumentNotes []struct {
		Value        string `xml:",chardata"`
		AttrAudience string `xml:"Audience,attr"`
		AttrOrdinal  string `xml:"Ordinal,attr"`
		AttrTitle    string `xml:"Title,attr"`
		AttrType     string `xml:"Type,attr"`
	} `xml:"DocumentNotes>Note"`
	DocumentDistribution string `xml:"DocumentDistribution"`
	AggregateSeverity    string `xml:"AggregateSeverity"`
	DocumentReferences   []struct {
		AttrType    string `xml:"Type,attr"`
		URL         string `xml:"URL"`
		Description string `xml:"Description"`
	} `xml:"DocumentReferences>Reference"`
	Acknowledgments []struct {
		Name         string `xml:"Name"`
		Organization string `xml:"Organization"`
		URL          string `xml:"URL"`
		Description  string `xml:"Description"`
	} `xml:"Acknowledgments>Acknowledgment"`
	ProductTree *struct {
		Branch *struct {
			AttrName        string `xml:"Name,attr"`
			AttrType        string `xml:"Type,attr"`
			FullProductName []struct {
				Value         string `xml:",chardata"`
				AttrProductID string `xml:"ProductID,attr"`
				AttrCpe       string `xml:"CPE,attr"`
			} `xml:"FullProductName"`
		} `xml:"Branch"`
		FullProductName []struct {
			Value         string `xml:",chardata"`
			AttrProductID string `xml:"ProductID,attr"`
			AttrCpe       string `xml:"CPE,attr"`
		} `xml:"FullProductName"`
		Relationship struct {
			AttrProductReference          string `xml:"ProductReference,attr"`
			AttrRelationshipType          string `xml:"RelationshipType,attr"`
			AttrRelatesToProductReference string `xml:"RelatesToProductReference,attr"`
			FullProductName               []struct {
				Value         string `xml:",chardata"`
				AttrProductID string `xml:"ProductID,attr"`
				AttrCpe       string `xml:"CPE,attr"`
			} `xml:"FullProductName"`
		} `xml:"Relationship"`
		ProductGroups []struct {
			Description string   `xml:"Description"`
			ProductID   []string `xml:"ProductID"`
		} `xml:"ProductGroups>Group"`
	} `xml:"ProductTree"`
	Vulnerability []struct {
		AttrOrdinal string `xml:"Ordinal,attr"`
		Title       string `xml:"Title"`
		ID          string `xml:"ID"`
		Notes       []struct {
			Value       string `xml:",chardata"`
			AttrOrdinal string `xml:"Ordinal,attr"`
			AttrTitle   string `xml:"Title,attr"`
			// General, Details, Description, Summary, FAQ, Legal Disclaimer, Other,
			AttrType     string `xml:"Type,attr"`
			AttrAudience string `xml:"Audience,attr"`
		} `xml:"Notes>Note"`
		DiscoveryDate Mstime `xml:"DiscoveryDate"`
		ReleaseDate   Mstime `xml:"ReleaseDate"`
		Involvements  []struct {
			// Vendor, Discoverer, Coordinator, User, Other
			Party string `xml:"Party,attr"`
			// Open, Disputed, In Progress, Completed, Contact Attempted, Not Contacted
			Status      string `xml:"Status,attr"`
			Description string `xml:"Description"`
		} `xml:"Involvements>Involvement"`
		Description     string `xml:"Description"`
		CVE             string `xml:"CVE"`
		CWE             string `xml:"CWE"`
		ProductStatuses []struct {
			// First Affected, Known Affected, Known Not Affected, First Fixed, Fixed, Recommended, Last Affected,
			AttrType  string   `xml:"Type,attr"`
			ProductID []string `xml:"ProductID"`
		} `xml:"ProductStatuses>Status"`
		Threats []struct {
			// Impact, Exploit Status, Target Set
			AttrType    string   `xml:"Type,attr"`
			AttrDate    Mstime   `xml:"Date,attr"`
			Description string   `xml:"Description"`
			GroupID     string   `xml:"GroupID"`
			ProductID   []string `xml:"ProductID"`
		} `xml:"Threats>Threat"`
		CVSSScoreSets []struct {
			// 0.0 – 10.0
			BaseScore float64 `xml:"BaseScore"`
			// 0.0 – 10.0
			TemporalScore float64 `xml:"TemporalScore"`
			// 0.0 – 10.0
			EnvironmentalScore float64 `xml:"EnvironmentalScore"`
			// 76 characters
			Vector    string   `xml:"Vector"`
			ProductID []string `xml:"ProductID"`
		} `xml:"CVSSScoreSets>ScoreSet"`
		Remediations []struct {
			// Workaround, Mitigation, Vendor Fix, None Available, Will Not Fix
			AttrType        string   `xml:"Type,attr"`
			AffectedFiles   []string `xml:"AffectedFiles>AffectedFile"`
			Description     string   `xml:"Description"`
			ProductID       []string `xml:"ProductID"`
			Entitlement     string   `xml:"Entitlement"`
			GroupID         string   `xml:"GroupID"`
			RestartRequired string   `xml:"RestartRequired"`
			SubType         string   `xml:"SubType"`
			Supercedence    string   `xml:"Supercedence"`
			URL             string   `xml:"URL"`
		} `xml:"Remediations>Remediation"`
		References []struct {
			// External, Self
			AttrType    string `xml:"Type,attr"`
			URL         string `xml:"URL"`
			Description string `xml:"Description"`
		} `xml:"References>Reference"`
		Acknowledgments []struct {
			Name         string `xml:"Name"`
			Organization string `xml:"Organization"`
			URL          string `xml:"URL"`
			Description  string `xml:"Description"`
		} `xml:"Acknowledgments>Acknowledgment"`
		RevisionHistory []struct {
			Date        Mstime  `xml:"Date"`
			Description string  `xml:"Description"`
			Number      float64 `xml:"Number"`
		} `xml:"RevisionHistory>Revision"`
	} `xml:"Vulnerability"`
}

// Mstime :
type Mstime struct {
	time.Time
}

// UnmarshalXML :
func (m *Mstime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var timeStr string
	if err := d.DecodeElement(&timeStr, &start); err != nil {
		return err
	}
	format := "2006-01-02T15:04:05"
	if strings.HasSuffix(timeStr, "Z") {
		format = "2006-01-02T15:04:05Z"
	}
	t, err := time.Parse(format, timeStr)
	if err != nil {
		return err
	}
	*m = Mstime{t}
	return nil
}

// MicrosoftBulletinSearch :
type MicrosoftBulletinSearch struct {
	DatePosted        string `xlsx:"0"`
	BulletinID        string `xlsx:"1"`
	BulletinKB        string `xlsx:"2"`
	Severity          string `xlsx:"3"`
	Impact            string `xlsx:"4"`
	Title             string `xlsx:"5"`
	AffectedProduct   string `xlsx:"6"`
	ComponentKB       string `xlsx:"7"`
	AffectedComponent string `xlsx:"8"`
	Supersedes        string `xlsx:"11"`
	Reboot            string `xlsx:"12"`
	CVEs              string `xlsx:"13"`
}

// MicrosoftCVE :
type MicrosoftCVE struct {
	ID                       int64                    `json:"-"`
	Title                    string                   `json:"title" gorm:"type:varchar(255)"`
	Description              string                   `json:"description" gorm:"type:text"`
	FAQ                      string                   `json:"faq" gorm:"type:text"`
	CveID                    string                   `json:"cve_id" gorm:"type:varchar(255);index:idx_microsoft_cves_cveid"`
	CWE                      string                   `json:"cwe" gorm:"type:varchar(255)"`
	MicrosoftProductStatuses []MicrosoftProductStatus `json:"microsoft_product_statuses"`
	Impact                   []MicrosoftThreat        `json:"impact"`
	Severity                 []MicrosoftThreat        `json:"severity"`
	ExploitStatus            string                   `json:"exploit_status" gorm:"type:varchar(255)"`
	Mitigation               string                   `json:"mitigation" gorm:"type:text"`
	Workaround               string                   `json:"workaround" gorm:"type:text"`
	VendorFix                []MicrosoftRemediation   `json:"vendor_fix"`
	NoneAvailable            []MicrosoftRemediation   `json:"none_available"`
	WillNotFix               []MicrosoftRemediation   `json:"will_not_fix"`
	KBIDs                    []MicrosoftKBID          `json:"kb_ids"`
	References               []MicrosoftReference     `json:"references"`
	ScoreSets                []MicrosoftScoreSet      `json:"score_sets"`
	PublishDate              time.Time                `json:"publish_date" gorm:"type:time"`
	LastUpdateDate           time.Time                `json:"last_update_date" gorm:"type:time"`
}

// MicrosoftReference :
type MicrosoftReference struct {
	ID             int64 `json:"-"`
	MicrosoftCVEID int64 `json:"-" gorm:"index:idx_microsoft_reference_microsoft_cve_id"`
	// External, Self
	AttrType    string `json:"type" gorm:"type:varchar(255)"`
	URL         string `json:"url" gorm:"type:varchar(255)"`
	Description string `json:"description" gorm:"type:text"`
}

// MicrosoftKBID :
type MicrosoftKBID struct {
	ID             int64  `json:"-"`
	MicrosoftCVEID int64  `json:"-" gorm:"index:idx_microsoft_kb_id_microsoft_cve_id"`
	KBID           string `json:"kb_id" gorm:"type:varchar(255)"`
}

// MicrosoftProductStatus :
type MicrosoftProductStatus struct {
	ID             int64              `json:"-"`
	MicrosoftCVEID int64              `json:"-" gorm:"index:idx_microsoft_product_status_microsoft_cve_id"`
	Products       []MicrosoftProduct `json:"products" gorm:"foreignKey:MicrosoftCVEID;references:MicrosoftCVEID"`
	ProductStatus  string             `json:"product_status" gorm:"type:varchar(255)"`
}

// MicrosoftThreat :
type MicrosoftThreat struct {
	ID             int64              `json:"-"`
	MicrosoftCVEID int64              `json:"-" gorm:"index:idx_microsoft_threat_microsoft_cve_id"`
	Description    string             `json:"description" gorm:"type:text"`
	Products       []MicrosoftProduct `json:"products" gorm:"foreignKey:MicrosoftCVEID;references:MicrosoftCVEID"`
	AttrType       string             `json:"-" gorm:"type:varchar(255)"`
}

// MicrosoftRemediation :
type MicrosoftRemediation struct {
	ID              int64              `json:"-"`
	MicrosoftCVEID  int64              `json:"-" gorm:"index:idx_microsoft_remediation_microsoft_cve_id"`
	Description     string             `json:"description" gorm:"type:text"`
	Products        []MicrosoftProduct `json:"products" gorm:"foreignKey:MicrosoftCVEID;references:MicrosoftCVEID"`
	Entitlement     string             `json:"entitlement" gorm:"type:varchar(255)"`
	RestartRequired string             `json:"restart_required" gorm:"type:varchar(255)"`
	SubType         string             `json:"sub_type" gorm:"type:varchar(255)"`
	Supercedence    string             `json:"supercedence" gorm:"type:text"`
	URL             string             `json:"url" gorm:"type:varchar(255)"`
	AttrType        string             `json:"-" gorm:"type:varchar(255)"`
}

// MicrosoftScoreSet :
type MicrosoftScoreSet struct {
	ID                 int64              `json:"-"`
	MicrosoftCVEID     int64              `json:"-" gorm:"index:idx_microsoft_score_set_microsoft_cve_id"`
	BaseScore          float64            `json:"base_score"`
	TemporalScore      float64            `json:"temporal_score"`
	EnvironmentalScore float64            `json:"environmental_score"`
	Vector             string             `json:"vector" gorm:"type:varchar(255)"`
	Products           []MicrosoftProduct `json:"products" gorm:"foreignKey:MicrosoftCVEID;references:MicrosoftCVEID"`
}

// MicrosoftProduct :
type MicrosoftProduct struct {
	ID             int64  `json:"-"`
	MicrosoftCVEID int64  `json:"-" gorm:"index:idx_microsoft_product_microsoft_cve_id"`
	Category       string `json:"-" gorm:"type:varchar(255)"`
	ProductID      string `json:"product_id" gorm:"type:varchar(255)"`
	ProductName    string `json:"product_name" gorm:"type:varchar(255)"`
}

// MicrosoftKBRelation :
type MicrosoftKBRelation struct {
	ID           int64  `json:"-"`
	KBID         string `json:"kbid" gorm:"type:varchar(255);index:idx_microsoft_relation_kb_id"`
	SupersededBy []MicrosoftSupersededBy
}

// MicrosoftSupersededBy :
type MicrosoftSupersededBy struct {
	ID                    int64  `json:"-"`
	MicrosoftKBRelationID int64  `json:"-" gorm:"index:idx_microsoft_superseded_by_microsoft_kb_relation_id"`
	KBID                  string `json:"kbid" gorm:"type:varchar(255);index:idx_microsoft_superseded_by_kb_id"`
}

// ConvertMicrosoft :
func ConvertMicrosoft(cveXMLs []MicrosoftXML, cveXls []MicrosoftBulletinSearch) (cves []MicrosoftCVE, msProducts []MicrosoftProduct) {
	uniqCve := map[string]MicrosoftCVE{}
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

			var productStatuses []MicrosoftProductStatus
			for i, p := range vuln.ProductStatuses {
				var products []MicrosoftProduct
				for _, productID := range p.ProductID {
					product := MicrosoftProduct{
						Category:    fmt.Sprintf("MicrosoftProductStatus:%d", i),
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				status := MicrosoftProductStatus{
					Products:      products,
					ProductStatus: p.AttrType,
				}
				productStatuses = append(productStatuses, status)
			}

			var exploitStatus string
			uniqImpact := map[string]MicrosoftThreat{}
			uniqSeverity := map[string]MicrosoftThreat{}
			for _, t := range vuln.Threats {
				var products []MicrosoftProduct
				for _, productID := range t.ProductID {
					product := MicrosoftProduct{
						Category:    "MicrosoftThreat",
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				threat := MicrosoftThreat{
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

			var impact, severity []MicrosoftThreat
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

			uniqScoreSets := map[string]MicrosoftScoreSet{}
			for _, s := range vuln.CVSSScoreSets {
				var products []MicrosoftProduct
				for _, productID := range s.ProductID {
					product := MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				scoreSet := MicrosoftScoreSet{
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

			var scoreSets []MicrosoftScoreSet
			index = 0
			for _, scoreSet := range uniqScoreSets {
				for j := range scoreSet.Products {
					scoreSet.Products[j].Category = fmt.Sprintf("MicrosoftScoreSet:%d", index)
				}
				scoreSets = append(scoreSets, scoreSet)
				index = index + 1
			}

			var mitigation, workaround string
			var vendorFix, noneAvailable, willNotFix []MicrosoftRemediation
			uniqKBIDs := map[string]bool{}
			for _, r := range vuln.Remediations {
				var products []MicrosoftProduct
				for _, productID := range r.ProductID {
					product := MicrosoftProduct{
						ProductID:   productID,
						ProductName: uniqProduct[productID],
					}
					products = append(products, product)
				}
				remediation := MicrosoftRemediation{
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

			var kbIDs []MicrosoftKBID
			for kbID := range uniqKBIDs {
				kbIDs = append(kbIDs, MicrosoftKBID{KBID: kbID})
			}

			var references []MicrosoftReference
			for _, r := range vuln.References {
				ref := MicrosoftReference{
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

			uniqCve[vuln.CVE] = MicrosoftCVE{
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
		msProduct := MicrosoftProduct{
			ProductID:   id,
			ProductName: name,
		}
		msProducts = append(msProducts, msProduct)
	}

	sort.Slice(msProducts, func(i, j int) bool {
		return msProducts[i].ProductID < msProducts[j].ProductID
	})

	// csv
	cveBulletinSearch := map[string][]MicrosoftBulletinSearch{}
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

		uniqImpact := map[string]MicrosoftThreat{}
		uniqSeverity := map[string]MicrosoftThreat{}
		uniqKBIDs := map[string]bool{}
		var vendorFix []MicrosoftRemediation
		var title string
		var publishDate time.Time
		for _, bs := range bss {
			var products []MicrosoftProduct
			if len(bs.AffectedProduct) != 0 {
				product := getProductFromName(msProducts, bs.AffectedProduct)
				products = append(products, product)
			}
			if len(bs.AffectedComponent) != 0 {
				product := getProductFromName(msProducts, bs.AffectedComponent)
				products = append(products, product)
			}

			impact := MicrosoftThreat{
				Description: bs.Impact,
				Products:    append([]MicrosoftProduct(nil), products...),
				AttrType:    "Impact",
			}
			if i, ok := uniqImpact[bs.Impact]; ok {
				impact.Products = append(impact.Products, i.Products...)
			}
			uniqImpact[bs.Impact] = impact

			severity := MicrosoftThreat{
				Description: bs.Severity,
				Products:    append([]MicrosoftProduct(nil), products...),
				AttrType:    "Severity",
			}
			if s, ok := uniqSeverity[bs.Severity]; ok {
				severity.Products = append(severity.Products, s.Products...)
			}
			uniqSeverity[bs.Severity] = severity

			rem := MicrosoftRemediation{
				Products:        append([]MicrosoftProduct(nil), products...),
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

		var impact, severity []MicrosoftThreat
		var kbIDs []MicrosoftKBID
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
			kbID := MicrosoftKBID{
				KBID: k,
			}
			kbIDs = append(kbIDs, kbID)
		}

		uniqCve[cveID] = MicrosoftCVE{
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

func getProductFromName(msProducts []MicrosoftProduct, productName string) MicrosoftProduct {
	for _, msp := range msProducts {
		if productName == msp.ProductName {
			return msp
		}
	}
	return MicrosoftProduct{
		ProductName: productName,
	}
}

// ConvertMicrosoftKBRelation :
func ConvertMicrosoftKBRelation(kbRelationJSON map[string][]string) []MicrosoftKBRelation {
	kbRelations := []MicrosoftKBRelation{}

	for kbid, supersededbyKBIDs := range kbRelationJSON {
		supersededby := []MicrosoftSupersededBy{}
		for _, kbid := range supersededbyKBIDs {
			supersededby = append(supersededby, MicrosoftSupersededBy{
				KBID: kbid,
			})
		}
		kbRelations = append(kbRelations, MicrosoftKBRelation{
			KBID:         kbid,
			SupersededBy: supersededby,
		})
	}

	return kbRelations
}
