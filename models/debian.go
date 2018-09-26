package models

type DebianJSON map[string]DebianCveMap

type DebianCveMap map[string]DebianCveJSON

type DebianCveJSON struct {
	Scope       string                       `json:"scope"`
	Debianbug   int                          `json:"debianbug"`
	Description string                       `json:"description"`
	Releases    map[string]DebianReleaseJSON `json:"releases"`
}

type DebianReleaseJSON struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

type DebianCVE struct {
	ID          int64
	CveID       string
	Scope       string
	Description string `sql:"type:text"`
	Package     []DebianPackage
}

type DebianPackage struct {
	ID          int64
	DebianCVEID int64 `sql:"type:bigint REFERENCES debian_cves(id)"`
	PackageName string
	Release     []DebianRelease
}

type DebianRelease struct {
	ID              int64
	DebianPackageID int64 `sql:"type:bigint REFERENCES debian_packages(id)"`
	ProductName     string
	Status          string
	FixedVersion    string
	Urgency         string
	Version         string
}
