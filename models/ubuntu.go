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

	PublicDateAtUSN   time.Time
	CRD               time.Time
	Candidate         string
	PublicDate        time.Time
	References        []UbuntuReference
	Description       string
	UbuntuDescription string
	Notes             []UbuntuNote
	Bugs              []UbuntuBug
	Priority          string
	DiscoveredBy      string
	AssignedTo        string
	Patches           []UbuntuPatch
	UpstreamLinks     []UbuntuUpstream
}

type UbuntuReference struct {
	ID          int64 `json:"-"`
	UbuntuCVEID int64 `json:"-"`
	Reference   string
}

type UbuntuNote struct {
	ID          int64 `json:"-"`
	UbuntuCVEID int64 `json:"-"`
	Note        string
}

type UbuntuBug struct {
	ID          int64 `json:"-"`
	UbuntuCVEID int64 `json:"-"`
	Bug         string
}

type UbuntuPatch struct {
	ID          int64 `json:"-"`
	UbuntuCVEID int64 `json:"-"`
	PackageName string
	Patches     []UbuntuReleasePatch
}

type UbuntuReleasePatch struct {
	ID            int64 `json:"-"`
	UbuntuPatchID int64 `json:"-"`
	ReleaseName   string
	Status        string
	Note          string
}

type UbuntuUpstream struct {
	ID          int64 `json:"-"`
	UbuntuCVEID int64 `json:"-"`
	PackageName string
	Links       []UbuntuUpstreamLink
}

type UbuntuUpstreamLink struct {
	ID               int64 `json:"-"`
	UbuntuUpstreamID int64 `json:"-"`
	Link             string
}
