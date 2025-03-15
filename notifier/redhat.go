package notifier

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/vulsio/gost/config"
	"github.com/vulsio/gost/models"
)

// ClearIDRedhat :
func ClearIDRedhat(cve *models.RedhatCVE) {
	cve.ID = 0
	cve.Bugzilla.RedhatCVEID = 0
	cve.Cvss.RedhatCVEID = 0
	cve.Cvss3.RedhatCVEID = 0

	affectedReleases := cve.AffectedRelease
	cve.AffectedRelease = []models.RedhatAffectedRelease{}
	for _, a := range affectedReleases {
		a.RedhatCVEID = 0
		cve.AffectedRelease = append(cve.AffectedRelease, a)
	}

	packageState := cve.PackageState
	cve.PackageState = []models.RedhatPackageState{}
	for _, p := range packageState {
		p.RedhatCVEID = 0
		cve.PackageState = append(cve.PackageState, p)
	}

	details := cve.Details
	cve.Details = []models.RedhatDetail{}
	for _, d := range details {
		d.RedhatCVEID = 0
		cve.Details = append(cve.Details, d)
	}

	references := cve.References
	cve.References = []models.RedhatReference{}
	for _, r := range references {
		r.RedhatCVEID = 0
		cve.References = append(cve.References, r)
	}

}

// DiffRedhat returns the difference between the old and new CVE information
func DiffRedhat(before, after *models.RedhatCVE, config config.RedhatWatchCve) (body string) {
	if config.ThreatSeverity {
		if before.ThreatSeverity != after.ThreatSeverity {
			body += fmt.Sprintf("\nThreat Secirity\n------------------\n[old]\n%v\n\n[new]\n%v\n",
				before.ThreatSeverity, after.ThreatSeverity)
		}
	}

	if config.Statement {
		if before.Statement != after.Statement {
			body += fmt.Sprintf("\nStatement\n------------------\n[old]\n%v\n[new]\n\n%v\n\n",
				before.Statement, after.Statement)
		}
	}

	if config.Acknowledgement {
		if before.Acknowledgement != after.Acknowledgement {
			body += fmt.Sprintf("\nAcknowledgement\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				before.Acknowledgement, after.Acknowledgement)
		}
	}

	if config.Mitigation {
		if before.Mitigation != after.Mitigation {
			body += fmt.Sprintf("\nMitigation\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				before.Mitigation, after.Mitigation)
			return
		}
	}

	if config.Bugzilla {
		if !reflect.DeepEqual(before.Bugzilla, after.Bugzilla) {
			body += fmt.Sprintf(`
Bugzilla
------------------
[old]
BugzillaID: %s
Descriptiion: %s
URL: %s

[new]
BugzillaID: %s
Descriptiion: %s
URL: %s
`,
				before.Bugzilla.BugzillaID, before.Bugzilla.Description, before.Bugzilla.URL,
				after.Bugzilla.BugzillaID, after.Bugzilla.Description, after.Bugzilla.URL)
		}
	}

	if config.Cvss {
		if !reflect.DeepEqual(before.Cvss, after.Cvss) {
			body += fmt.Sprintf(`
CVSS
------------------
[old]
Base Score: %s
Vector: %s
Status: %s

[new]
Base Score: %s
Vector: %s
Status: %s
`,
				before.Cvss.CvssBaseScore, before.Cvss.CvssScoringVector, before.Cvss.Status,
				after.Cvss.CvssBaseScore, after.Cvss.CvssScoringVector, after.Cvss.Status)
		}
	}

	if config.Cvss3 {
		if !reflect.DeepEqual(before.Cvss3, after.Cvss3) {
			body += fmt.Sprintf(`
CVSSv3
------------------
[old]
Base Score: %s
Vector: %s
Status: %s

[new]
Base Score: %s
Vector: %s
Status: %s
`,
				before.Cvss3.Cvss3BaseScore, before.Cvss3.Cvss3ScoringVector, before.Cvss3.Status,
				after.Cvss3.Cvss3BaseScore, after.Cvss3.Cvss3ScoringVector, after.Cvss3.Status)
		}
	}

	if config.AffectedRelease && (len(before.AffectedRelease) > 0 || len(after.AffectedRelease) > 0) {
		oldAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, r := range before.AffectedRelease {
			oldAffectedRelease[r.ProductName+"#"+r.Package] = r
		}

		newAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, r := range after.AffectedRelease {
			newAffectedRelease[r.ProductName+"#"+r.Package] = r
		}

		for key, nar := range newAffectedRelease {
			isNew := false

			oar, ok := oldAffectedRelease[key]
			if ok {
				if !reflect.DeepEqual(oar, nar) {
					isNew = true
				}
			} else {
				isNew = true
			}

			if !isNew {
				continue
			}

			body += fmt.Sprintf(`
Affected Release
------------------
[old]
Product Name: %s
Advisory: %s
Package: %s
CPE: %s
Release Date: %s

[new]
Product Name: %s
Advisory: %s
Package: %s
CPE: %s
Release Date: %s
`,
				oar.ProductName, oar.Advisory, oar.Package, oar.Cpe, oar.ReleaseDate,
				nar.ProductName, nar.Advisory, nar.Package, nar.Cpe, nar.ReleaseDate)
		}
	}

	if config.PackageState && (len(before.PackageState) > 0 || len(after.PackageState) > 0) {
		oldPackageState := map[string]models.RedhatPackageState{}
		for _, s := range before.PackageState {
			oldPackageState[s.ProductName+"#"+s.PackageName] = s
		}

		newPackageState := map[string]models.RedhatPackageState{}
		for _, s := range after.PackageState {
			newPackageState[s.ProductName+"#"+s.PackageName] = s
		}

		for key, nps := range newPackageState {
			isNew := false

			ops, ok := oldPackageState[key]
			if ok {
				if !reflect.DeepEqual(ops, nps) {
					isNew = true
				}
			} else {
				isNew = true
			}

			if !isNew {
				continue
			}

			body += fmt.Sprintf(`
Package State
------------------
[old]
Product Name: %s
Fix State: %s
Package Name: %s

[new]
Product Name: %s
Fix State: %s
Package Name: %s
`,
				ops.ProductName, ops.FixState, ops.PackageName,
				nps.ProductName, nps.FixState, nps.PackageName)
		}

	}

	if config.Reference && (len(before.References) > 0 || len(after.References) > 0) {
		if !reflect.DeepEqual(before.References, after.References) {
			ors := []string{}
			for _, r := range before.References {
				ors = append(ors, r.Reference)
			}

			nrs := []string{}
			for _, r := range after.References {
				nrs = append(nrs, r.Reference)
			}
			body += fmt.Sprintf(`
Reference
------------------
[old]
%s

[new]
%s
`,
				strings.Join(ors, "\n"), strings.Join(nrs, "\n"))
			return
		}
	}

	if config.Details && (len(before.Details) > 0 || len(after.Details) > 0) {
		if !reflect.DeepEqual(before.Details, after.Details) {
			ods := []string{}
			for _, d := range before.Details {
				ods = append(ods, d.Detail)
			}

			nds := []string{}
			for _, d := range after.Details {
				nds = append(nds, d.Detail)
			}

			body += fmt.Sprintf(`
Detail
------------------
[old]
%s

[new]
%s
`,
				strings.Join(ods, "\n"), strings.Join(nds, "\n"))
			return
		}
	}

	return body

}
