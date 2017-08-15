package models

import (
	"strings"
	"time"
)

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

type RedhatCVEJSON struct {
	ThreatSeverity       string                  `json:"threat_severity"`
	PublicDate           string                  `json:"public_date"`
	Bugzilla             RedhatBugzilla          `json:"bugzilla"`
	Cvss                 RedhatCvss              `json:"cvss"`
	Cvss3                RedhatCvss3             `json:"cvss3"`
	Iava                 string                  `json:"iava"`
	Cwe                  string                  `json:"cwe"`
	Statement            string                  `json:"statement"`
	Acknowledgement      string                  `json:"acknowledgement"`
	Mitigation           string                  `json:"mitigation"`
	AffectedRelease      []RedhatAffectedRelease `json:"affected_release"`
	PackageState         []RedhatPackageState    `json:"package_state"`
	Name                 string                  `json:"name"`
	DocumentDistribution string                  `json:"document_distribution"`

	Details    []string `json:"details" gorm:"-"`
	References []string `json:"references" gorm:"-"`
}

type RedhatCVE struct {
	ID int64

	// gorm can't handle embedded struct
	ThreatSeverity       string
	PublicDate           time.Time
	Bugzilla             RedhatBugzilla
	Cvss                 RedhatCvss
	Cvss3                RedhatCvss3
	Iava                 string
	Cwe                  string
	Statement            string
	Acknowledgement      string
	Mitigation           string
	AffectedRelease      []RedhatAffectedRelease
	PackageState         []RedhatPackageState
	Name                 string
	DocumentDistribution string

	Details    []RedhatDetail
	References []RedhatReference
}

func (r RedhatCVE) GetDetail(sep string) string {
	var details []string
	for _, d := range r.Details {
		details = append(details, d.Detail)
	}
	return strings.Join(details, sep)
}

func (r RedhatCVE) GetPackages(sep string) (result string) {
	pkgs := map[string]struct{}{}
	for _, d := range r.PackageState {
		pkgs[d.PackageName] = struct{}{}
	}

	var pkgNames []string
	for p := range pkgs {
		pkgNames = append(pkgNames, p)
	}

	return strings.Join(pkgNames, sep)
}

type RedhatDetail struct {
	RedhatCVEID int64 `sql:"type:bigint REFERENCES redhat_cves(id)"`
	Detail      string
}

type RedhatReference struct {
	RedhatCVEID int64 `sql:"type:bigint REFERENCES redhat_cves(id)"`
	Reference   string
}

type RedhatBugzilla struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)"`
	Description string `json:"description"`
	BugzillaID  string `json:"id"`
	URL         string `json:"url"`
}

type RedhatCvss struct {
	RedhatCVEID       int64  `sql:"type:bigint REFERENCES redhat_cves(id)"`
	CvssBaseScore     string `json:"cvss_base_score"`
	CvssScoringVector string `json:"cvss_scoring_vector"`
	Status            string `json:"status"`
}

type RedhatCvss3 struct {
	RedhatCVEID        int64  `sql:"type:bigint REFERENCES redhat_cves(id)"`
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Status             string `json:"status"`
}

type RedhatAffectedRelease struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)"`
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	Cpe         string `json:"cpe"`
}

type RedhatPackageState struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)"`
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	Cpe         string `json:"cpe"`
}
