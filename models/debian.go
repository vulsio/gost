package models

import "golang.org/x/exp/maps"

// DebianJSON :
type DebianJSON map[string]DebianCveMap

// DebianCveMap :
type DebianCveMap map[string]DebianCveJSON

// DebianCveJSON :
type DebianCveJSON struct {
	Scope       string                       `json:"scope"`
	Debianbug   int                          `json:"debianbug"`
	Description string                       `json:"description"`
	Releases    map[string]DebianReleaseJSON `json:"releases"`
}

// DebianReleaseJSON :
type DebianReleaseJSON struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

// DebianCVE :
type DebianCVE struct {
	ID          int64  `json:"-"`
	CveID       string `gorm:"index:idx_debian_cves_cveid;type:varchar(255);"`
	Scope       string `gorm:"type:varchar(255)"`
	Description string
	Package     []DebianPackage
}

// DebianPackage :
type DebianPackage struct {
	ID          int64  `json:"-"`
	DebianCVEID int64  `json:"-" gorm:"index:idx_debian_packages_debian_cve_id"`
	PackageName string `gorm:"type:varchar(255);index:idx_debian_packages_package_name"`
	Release     []DebianRelease
}

// DebianRelease :
type DebianRelease struct {
	ID              int64  `json:"-"`
	DebianPackageID int64  `json:"-" gorm:"index:idx_debian_releases_debian_package_id"`
	ProductName     string `gorm:"type:varchar(255);index:idx_debian_releases_product_name"`
	Status          string `gorm:"type:varchar(255);index:idx_debian_releases_status"`
	FixedVersion    string `gorm:"type:varchar(255);"`
	Urgency         string `gorm:"type:varchar(255);"`
	Version         string `gorm:"type:varchar(255);"`
}

// ConvertDebian :
func ConvertDebian(cveJSONs DebianJSON) []DebianCVE {
	uniqCve := map[string]DebianCVE{}
	for pkgName, cveMap := range cveJSONs {
		for cveID, cve := range cveMap {
			var releases []DebianRelease
			for release, releaseInfo := range cve.Releases {
				r := DebianRelease{
					ProductName:  release,
					Status:       releaseInfo.Status,
					FixedVersion: releaseInfo.FixedVersion,
					Urgency:      releaseInfo.Urgency,
					Version:      releaseInfo.Repositories[release],
				}
				releases = append(releases, r)
			}

			pkg := DebianPackage{
				PackageName: pkgName,
				Release:     releases,
			}

			pkgs := []DebianPackage{pkg}
			if oldCve, ok := uniqCve[cveID]; ok {
				pkgs = append(pkgs, oldCve.Package...)
			}

			uniqCve[cveID] = DebianCVE{
				CveID:       cveID,
				Scope:       cve.Scope,
				Description: cve.Description,
				Package:     pkgs,
			}
		}
	}
	return maps.Values(uniqCve)
}
