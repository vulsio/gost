package models

import (
	"strings"
	"time"
)

//TODO addFetchMeta

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

type RedhatCVEJSONAffectedReleaseArray struct {
	AffectedRelease []RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEJSONAffectedReleaseObject struct {
	AffectedRelease RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEJSONPackageStateArray struct {
	PackageState []RedhatPackageState `json:"package_state"`
}

type RedhatCVEJSONPackageStateObject struct {
	PackageState RedhatPackageState `json:"package_state"`
}

type RedhatCVE struct {
	ID int64 `json:",omitempty"`

	// gorm can't handle embedded struct
	ThreatSeverity       string
	PublicDate           time.Time
	Bugzilla             RedhatBugzilla
	Cvss                 RedhatCvss
	Cvss3                RedhatCvss3
	Iava                 string
	Cwe                  string
	Statement            string `sql:"type:text"`
	Acknowledgement      string `sql:"type:text"`
	Mitigation           string `sql:"type:text"`
	AffectedRelease      []RedhatAffectedRelease
	PackageState         []RedhatPackageState
	Name                 string
	DocumentDistribution string `sql:"type:text"`

	Details    []RedhatDetail    `json:",omitempty"`
	References []RedhatReference `json:",omitempty"`
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
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	Detail      string `sql:"type:text"`
}

type RedhatReference struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	Reference   string `sql:"type:text"`
}

type RedhatBugzilla struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	Description string `json:"description" sql:"type:text"`

	BugzillaID string `json:"id"`
	URL        string `json:"url"`
}

type RedhatCvss struct {
	RedhatCVEID       int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	CvssBaseScore     string `json:"cvss_base_score"`
	CvssScoringVector string `json:"cvss_scoring_vector"`
	Status            string `json:"status"`
}

type RedhatCvss3 struct {
	RedhatCVEID        int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Status             string `json:"status"`
}

type RedhatAffectedRelease struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	Cpe         string `json:"cpe"`
}

type RedhatPackageState struct {
	RedhatCVEID int64  `sql:"type:bigint REFERENCES redhat_cves(id)" json:",omitempty"`
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	Cpe         string `json:"cpe"`
}
