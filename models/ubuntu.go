package models

import "time"

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

type UbuntuPatchJSON struct {
	Status string
	Note   string
}

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
	DiscoveredBy      string            `json:"discovered_by" gorm:"type:varchar(255)"`
	AssignedTo        string            `json:"assigned_to" gorm:"type:varchar(255)"`
	Patches           []UbuntuPatch     `json:"patches"`
	Upstreams         []UbuntuUpstream  `json:"upstreams"`
}

type UbuntuReference struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_reference_ubuntu_cve_id"`
	Reference   string `json:"reference" gorm:"type:text"`
}

type UbuntuNote struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_note_ubuntu_cve_id"`
	Note        string `json:"note" gorm:"type:text"`
}

type UbuntuBug struct {
	ID          int64  `json:"-"`
	UbuntuCVEID int64  `json:"-" gorm:"index:idx_ubuntu_bug_ubuntu_cve_id"`
	Bug         string `json:"bug" gorm:"type:text"`
}

type UbuntuPatch struct {
	ID             int64                `json:"-"`
	UbuntuCVEID    int64                `json:"-" gorm:"index:idx_ubuntu_patch_ubuntu_cve_id"`
	PackageName    string               `json:"package_name" gorm:"type:varchar(255);index:idx_ubuntu_patch_package_name"`
	ReleasePatches []UbuntuReleasePatch `json:"release_patches"`
}

type UbuntuReleasePatch struct {
	ID            int64  `json:"-"`
	UbuntuPatchID int64  `json:"-" gorm:"index:idx_ubuntu_release_patch_ubuntu_patch_id"`
	ReleaseName   string `json:"release_name" gorm:"type:varchar(255);index:idx_ubuntu_release_patch_release_name"`
	Status        string `json:"status" gorm:"type:varchar(255);index:idx_ubuntu_release_patch_status"`
	Note          string `json:"note" gorm:"type:varchar(255)"`
}

type UbuntuUpstream struct {
	ID            int64                `json:"-"`
	UbuntuCVEID   int64                `json:"-" gorm:"index:idx_ubuntu_upstream_ubuntu_cve_id"`
	PackageName   string               `json:"package_name" gorm:"type:varchar(255)"`
	UpstreamLinks []UbuntuUpstreamLink `json:"upstream_links"`
}

type UbuntuUpstreamLink struct {
	ID               int64  `json:"-"`
	UbuntuUpstreamID int64  `json:"-" gorm:"index:idx_ubuntu_upstream_link_ubuntu_upstream_id"`
	Link             string `json:"link" gorm:"type:text"`
}
