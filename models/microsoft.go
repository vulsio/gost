package models

import (
	"encoding/xml"
	"strings"
	"time"
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
	ID                       int64                    `json:",omitempty"`
	Title                    string                   `json:"title"`
	Description              string                   `json:"description"`
	FAQ                      string                   `json:"faq"`
	CveID                    string                   `json:"cve_id"`
	CWE                      string                   `json:"cwe"`
	MicrosoftProductStatuses []MicrosoftProductStatus `json:"microsoft_product_statuses"`
	Impact                   []MicrosoftThreat        `json:"impact"`
	Severity                 []MicrosoftThreat        `json:"severity"`
	ExploitStatus            string                   `json:"exploit_status"`
	Mitigation               string                   `json:"mitigation"`
	Workaround               string                   `json:"workaround"`
	VendorFix                []MicrosoftRemediation   `json:"vendor_fix"`
	NoneAvailable            []MicrosoftRemediation   `json:"none_available"`
	WillNotFix               []MicrosoftRemediation   `json:"will_not_fix"`
	KBIDs                    []MicrosoftKBID          `json:"kb_ids"`
	References               []MicrosoftReference     `json:"references"`
	ScoreSets                []MicrosoftScoreSet      `json:"score_sets"`
	PublishDate              time.Time                `json:"publish_date"`
	LastUpdateDate           time.Time                `json:"last_update_date"`
}

// MicrosoftReference :
type MicrosoftReference struct {
	MicrosoftCVEID int64 `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	// External, Self
	AttrType    string `json:"type"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// MicrosoftKBID :
type MicrosoftKBID struct {
	MicrosoftCVEID int64  `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	KBID           string `json:"kb_id"`
}

// MicrosoftProductStatus :
type MicrosoftProductStatus struct {
	MicrosoftCVEID int64              `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	Products       []MicrosoftProduct `json:"products"`
	ProductStatus  string             `json:"product_status"`
}

// MicrosoftThreat :
type MicrosoftThreat struct {
	MicrosoftCVEID int64              `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	Description    string             `json:"description"`
	Products       []MicrosoftProduct `json:"products"`
}

// MicrosoftRemediation :
type MicrosoftRemediation struct {
	MicrosoftCVEID  int64              `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	Description     string             `json:"description"`
	Products        []MicrosoftProduct `json:"products"`
	Entitlement     string             `json:"entitlement"`
	RestartRequired string             `json:"restart_required"`
	SubType         string             `json:"sub_type"`
	Supercedence    string             `json:"supercedence"`
	URL             string             `json:"url"`
}

// MicrosoftScoreSet :
type MicrosoftScoreSet struct {
	MicrosoftCVEID     int64              `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	BaseScore          float64            `json:"base_score"`
	TemporalScore      float64            `json:"temporal_score"`
	EnvironmentalScore float64            `json:"environmental_score"`
	Vector             string             `json:"vector"`
	Products           []MicrosoftProduct `json:"products"`
}

// MicrosoftCveID :
type MicrosoftCveID struct {
	MicrosoftCVEID int64  `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	CveID          string `json:"cve_id"`
}

// MicrosoftProduct :
type MicrosoftProduct struct {
	MicrosoftCVEID int64  `sql:"type:bigint REFERENCES microsoft_cves(id)" json:",omitempty"`
	ProductID      string `json:"product_id"`
	ProductName    string `json:"product_name"`
}
