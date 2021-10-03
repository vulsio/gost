package models

import (
	"strings"
	"time"

	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// RedhatEntry :
type RedhatEntry struct {
	CveID             string        `json:"CVE"`
	Severity          string        `json:"severity"`
	PublicDate        time.Time     `json:"public_date"`
	Advisories        []interface{} `json:"advisories"`
	Bugzilla          string        `json:"bugzilla"`
	CvssScore         interface{}   `json:"cvss_score"`
	CvssScoringVector interface{}   `json:"cvss_scoring_vector"`
	CWE               string        `json:"CWE"`
	AffectedPackages  []interface{} `json:"affected_packages"`
	ResourceURL       string        `json:"resource_url"`
	Cvss3Score        float64       `json:"cvss3_score"`
}

// RedhatCVEJSON :
type RedhatCVEJSON struct {
	ThreatSeverity       string         `json:"threat_severity"`
	PublicDate           string         `json:"public_date"`
	Bugzilla             RedhatBugzilla `json:"bugzilla"`
	Cvss                 RedhatCvss     `json:"cvss"`
	Cvss3                RedhatCvss3    `json:"cvss3"`
	Iava                 string         `json:"iava"`
	Cwe                  string         `json:"cwe"`
	Statement            string         `json:"statement"`
	Acknowledgement      string         `json:"acknowledgement"`
	Mitigation           string         `json:"mitigation"`
	TempAffectedRelease  interface{}    `json:"affected_release"` // affected_release is array or object
	AffectedRelease      []RedhatAffectedRelease
	TempPackageState     interface{} `json:"package_state"` // package_state is array or object
	PackageState         []RedhatPackageState
	Name                 string `json:"name"`
	DocumentDistribution string `json:"document_distribution"`

	Details    []string `json:"details" gorm:"-"`
	References []string `json:"references" gorm:"-"`
}

// RedhatCVEJSONAffectedReleaseArray :
type RedhatCVEJSONAffectedReleaseArray struct {
	AffectedRelease []RedhatAffectedRelease `json:"affected_release"`
}

// RedhatCVEJSONAffectedReleaseObject :
type RedhatCVEJSONAffectedReleaseObject struct {
	AffectedRelease RedhatAffectedRelease `json:"affected_release"`
}

// RedhatCVEJSONPackageStateArray :
type RedhatCVEJSONPackageStateArray struct {
	PackageState []RedhatPackageState `json:"package_state"`
}

// RedhatCVEJSONPackageStateObject :
type RedhatCVEJSONPackageStateObject struct {
	PackageState RedhatPackageState `json:"package_state"`
}

// RedhatCVE :
type RedhatCVE struct {
	ID int64 `json:"-"`

	// gorm can't handle embedded struct
	ThreatSeverity       string    `gorm:"type:varchar(255)"`
	PublicDate           time.Time `gorm:"type:time"`
	Bugzilla             RedhatBugzilla
	Cvss                 RedhatCvss
	Cvss3                RedhatCvss3
	Iava                 string `gorm:"type:varchar(255)"`
	Cwe                  string `gorm:"type:varchar(255)"`
	Statement            string `gorm:"type:text"`
	Acknowledgement      string `gorm:"type:text"`
	Mitigation           string `gorm:"type:text"`
	AffectedRelease      []RedhatAffectedRelease
	PackageState         []RedhatPackageState
	Name                 string `gorm:"type:varchar(255);index:idx_redhat_cves_name"`
	DocumentDistribution string `gorm:"type:text"`

	Details    []RedhatDetail
	References []RedhatReference
}

// GetDetail returns details
func (r RedhatCVE) GetDetail(sep string) string {
	details := []string{}
	for _, d := range r.Details {
		details = append(details, d.Detail)
	}
	return strings.Join(details, sep)
}

// GetPackages returns package names
func (r RedhatCVE) GetPackages(sep string) (result string) {
	pkgs := map[string]struct{}{}
	for _, d := range r.PackageState {
		pkgs[d.PackageName] = struct{}{}
	}

	pkgNames := []string{}
	for p := range pkgs {
		pkgNames = append(pkgNames, p)
	}

	return strings.Join(pkgNames, sep)
}

// RedhatDetail :
type RedhatDetail struct {
	ID          int64  `json:"-"`
	RedhatCVEID int64  `json:"-" gorm:"index:idx_redhat_details_redhat_cve_id"`
	Detail      string `gorm:"type:text"`
}

// RedhatReference :
type RedhatReference struct {
	ID          int64  `json:"-"`
	RedhatCVEID int64  `json:"-" gorm:"index:idx_redhat_references_redhat_cve_id"`
	Reference   string `gorm:"type:text"`
}

// RedhatBugzilla :
type RedhatBugzilla struct {
	ID          int64  `json:"-"`
	RedhatCVEID int64  `json:"-" gorm:"index:idx_redhat_bugzillas_redhat_cve_id"`
	Description string `json:"description" gorm:"type:text"`

	BugzillaID string `json:"id" gorm:"type:varchar(255)"`
	URL        string `json:"url" gorm:"type:varchar(255)"`
}

// RedhatCvss :
type RedhatCvss struct {
	ID                int64  `json:"-"`
	RedhatCVEID       int64  `json:"-" gorm:"index:idx_redhat_cvsses_redhat_cve_id"`
	CvssBaseScore     string `json:"cvss_base_score" gorm:"type:varchar(255)"`
	CvssScoringVector string `json:"cvss_scoring_vector" gorm:"type:varchar(255)"`
	Status            string `json:"status" gorm:"type:varchar(255)"`
}

// RedhatCvss3 :
type RedhatCvss3 struct {
	ID                 int64  `json:"-"`
	RedhatCVEID        int64  `json:"-" gorm:"index:idx_redhat_cvss3_redhat_cve_id"`
	Cvss3BaseScore     string `json:"cvss3_base_score" gorm:"type:varchar(255)"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector" gorm:"type:varchar(255)"`
	Status             string `json:"status" gorm:"type:varchar(255)"`
}

// RedhatAffectedRelease :
type RedhatAffectedRelease struct {
	ID          int64  `json:"-"`
	RedhatCVEID int64  `json:"-" gorm:"index:idx_redhat_affected_releases_redhat_cve_id"`
	ProductName string `json:"product_name" gorm:"type:varchar(255)"`
	ReleaseDate string `json:"release_date" gorm:"type:varchar(255)"`
	Advisory    string `json:"advisory" gorm:"type:varchar(255)"`
	Package     string `json:"package" gorm:"type:varchar(255)"`
	Cpe         string `json:"cpe" gorm:"type:varchar(255)"`
}

// RedhatPackageState :
type RedhatPackageState struct {
	ID          int64  `json:"-"`
	RedhatCVEID int64  `json:"-" gorm:"index:idx_redhat_package_states_redhat_cve_id"`
	ProductName string `json:"product_name" gorm:"type:varchar(255)"`
	FixState    string `json:"fix_state" gorm:"type:varchar(255);index:idx_redhat_package_states_fix_state"`
	PackageName string `json:"package_name" gorm:"type:varchar(255);index:idx_redhat_package_states_package_name"`
	Cpe         string `json:"cpe" gorm:"type:varchar(255);index:idx_redhat_package_states_cpe"`
}

// ConvertRedhat :
func ConvertRedhat(cveJSONs []RedhatCVEJSON) (cves []RedhatCVE, err error) {
	for _, cve := range cveJSONs {
		details := []RedhatDetail{}
		for _, d := range cve.Details {
			d = util.TrimSpaceNewline(d)
			details = append(details, RedhatDetail{Detail: d})
		}

		references := []RedhatReference{}
		for _, r := range cve.References {
			r = util.TrimSpaceNewline(r)
			references = append(references, RedhatReference{Reference: r})
		}

		cve.Bugzilla.Description = util.TrimSpaceNewline(cve.Bugzilla.Description)
		cve.Statement = util.TrimSpaceNewline(cve.Statement)

		var publicDate time.Time
		if cve.PublicDate != "" {
			if strings.HasSuffix(cve.PublicDate, "Z") {
				publicDate, err = time.Parse("2006-01-02T15:04:05Z", cve.PublicDate)
			} else {
				publicDate, err = time.Parse("2006-01-02T15:04:05", cve.PublicDate)
			}
			if err != nil {
				return nil, xerrors.Errorf("Failed to parse date. date: %s err: %w", cve.PublicDate, err)
			}
		}

		// TODO: more efficient
		c := RedhatCVE{
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
