package models

import (
	"strings"
	"time"
)

// UbuntuCVEJSON :
type UbuntuCVEJSON struct {
	PublicDateAtUSN   time.Time
	CRD               time.Time
	Candidate         string
	PublicDate        time.Time
	References        []string
	Description       string
	UbuntuDescription string
	Notes             []string
	Bugs              []string
	Priority          string
	DiscoveredBy      string
	AssignedTo        string
	Patches           map[string]map[string]UbuntuPatchJSON
	UpstreamLinks     map[string][]string
}

// UbuntuPatchJSON :
type UbuntuPatchJSON struct {
	Status string
	Note   string
}

// UbuntuCVE :
type UbuntuCVE struct {
	ID int64 `json:"-"`

	PublicDateAtUSN   time.Time         `json:"public_data_at_usn"`
	CRD               time.Time         `json:"crd"`
	Candidate         string            `json:"candidate" gorm:"type:varchar(255);index:idx_ubuntu_cve_candidate"`
	PublicDate        time.Time         `json:"public_date"`
	References        []UbuntuReference `json:"references"`
	Description       string            `json:"description" gorm:"type:text"`
	UbuntuDescription string            `json:"ubuntu_description" gorm:"type:text"`
	Notes             []UbuntuNote      `json:"notes"`
	Bugs              []UbuntuBug       `json:"bugs"`
	Priority          string            `json:"priority" gorm:"type:varchar(255)"`
	DiscoveredBy      string            `json:"discovered_by" gorm:"type:text"`
	AssignedTo        string            `json:"assigned_to" gorm:"type:varchar(255)"`
	Patches           []UbuntuPatch     `json:"patches"`
	Upstreams         []UbuntuUpstream  `json:"upstreams"`
}

// UbuntuReference :
type UbuntuReference struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_reference_ubuntu_cve_id"`
	Reference   string `json:"reference" gorm:"type:text"`
}

// UbuntuNote :
type UbuntuNote struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_note_ubuntu_cve_id"`
	Note        string `json:"note" gorm:"type:text"`
}

// UbuntuBug :
type UbuntuBug struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_bug_ubuntu_cve_id"`
	Bug         string `json:"bug" gorm:"type:text"`
}

// UbuntuPatch :
type UbuntuPatch struct {
	ID             int64                `json:"-"`
	UbuntuCVEID    int64                `json:"-" gorm:"index:idx_ubuntu_patch_ubuntu_cve_id"`
	PackageName    string               `json:"package_name" gorm:"type:varchar(255);index:idx_ubuntu_patch_package_name"`
	ReleasePatches []UbuntuReleasePatch `json:"release_patches"`
}

// UbuntuReleasePatch :
type UbuntuReleasePatch struct {
	ID            int64  `json:"-"`
	UbuntuPatchID int64  `json:"-" gorm:"index:idx_ubuntu_release_patch_ubuntu_patch_id"`
	ReleaseName   string `json:"release_name" gorm:"type:varchar(255);index:idx_ubuntu_release_patch_release_name"`
	Status        string `json:"status" gorm:"type:varchar(255);index:idx_ubuntu_release_patch_status"`
	Note          string `json:"note" gorm:"type:varchar(255)"`
}

// UbuntuUpstream :
type UbuntuUpstream struct {
	ID            int64                `json:"-"`
	UbuntuCVEID   int64                `json:"-" gorm:"index:idx_ubuntu_upstream_ubuntu_cve_id"`
	PackageName   string               `json:"package_name" gorm:"type:varchar(255)"`
	UpstreamLinks []UbuntuUpstreamLink `json:"upstream_links"`
}

// UbuntuUpstreamLink :
type UbuntuUpstreamLink struct {
	ID               int64  `json:"-"`
	UbuntuUpstreamID int64  `json:"-" gorm:"index:idx_ubuntu_upstream_link_ubuntu_upstream_id"`
	Link             string `json:"link" gorm:"type:text"`
}

// ConvertUbuntu :
func ConvertUbuntu(cveJSONs []UbuntuCVEJSON) (cves []UbuntuCVE) {
	for _, cve := range cveJSONs {
		if strings.Contains(cve.Description, "** REJECT **") {
			continue
		}

		references := []UbuntuReference{}
		for _, r := range cve.References {
			references = append(references, UbuntuReference{Reference: r})
		}

		notes := []UbuntuNote{}
		for _, n := range cve.Notes {
			notes = append(notes, UbuntuNote{Note: n})
		}

		bugs := []UbuntuBug{}
		for _, b := range cve.Bugs {
			bugs = append(bugs, UbuntuBug{Bug: b})
		}

		patches := []UbuntuPatch{}
		for pkgName, p := range cve.Patches {
			var releasePatch []UbuntuReleasePatch
			for release, patch := range p {
				releasePatch = append(releasePatch, UbuntuReleasePatch{ReleaseName: release, Status: patch.Status, Note: patch.Note})
			}
			patches = append(patches, UbuntuPatch{PackageName: pkgName, ReleasePatches: releasePatch})
		}

		upstreams := []UbuntuUpstream{}
		for pkgName, u := range cve.UpstreamLinks {
			links := []UbuntuUpstreamLink{}
			for _, link := range u {
				links = append(links, UbuntuUpstreamLink{Link: link})
			}
			upstreams = append(upstreams, UbuntuUpstream{PackageName: pkgName, UpstreamLinks: links})
		}

		c := UbuntuCVE{
			PublicDateAtUSN:   cve.PublicDateAtUSN,
			CRD:               cve.CRD,
			Candidate:         cve.Candidate,
			PublicDate:        cve.PublicDate,
			References:        references,
			Description:       cve.Description,
			UbuntuDescription: cve.UbuntuDescription,
			Notes:             notes,
			Bugs:              bugs,
			Priority:          cve.Priority,
			DiscoveredBy:      cve.DiscoveredBy,
			AssignedTo:        cve.AssignedTo,
			Patches:           patches,
			Upstreams:         upstreams,
		}
		cves = append(cves, c)
	}

	return cves
}
