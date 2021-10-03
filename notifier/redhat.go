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
func DiffRedhat(old, new *models.RedhatCVE, config config.RedhatWatchCve) (body string) {
	if config.ThreatSeverity {
		if old.ThreatSeverity != new.ThreatSeverity {
			body += fmt.Sprintf("\nThreat Secirity\n------------------\n[old]\n%v\n\n[new]\n%v\n",
				old.ThreatSeverity, new.ThreatSeverity)
		}
	}

	if config.Statement {
		if old.Statement != new.Statement {
			body += fmt.Sprintf("\nStatement\n------------------\n[old]\n%v\n[new]\n\n%v\n\n",
				old.Statement, new.Statement)
		}
	}

	if config.Acknowledgement {
		if old.Acknowledgement != new.Acknowledgement {
			body += fmt.Sprintf("\nAcknowledgement\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				old.Acknowledgement, new.Acknowledgement)
		}
	}

	if config.Mitigation {
		if old.Mitigation != new.Mitigation {
			body += fmt.Sprintf("\nMitigation\n------------------\n[old]\n%v\n\n[new]\n%v\n\n",
				old.Mitigation, new.Mitigation)
			return
		}
	}

	if config.Bugzilla {
		if !reflect.DeepEqual(old.Bugzilla, new.Bugzilla) {
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
				old.Bugzilla.BugzillaID, old.Bugzilla.Description, old.Bugzilla.URL,
				new.Bugzilla.BugzillaID, new.Bugzilla.Description, new.Bugzilla.URL)
		}
	}

	if config.Cvss {
		if !reflect.DeepEqual(old.Cvss, new.Cvss) {
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
				old.Cvss.CvssBaseScore, old.Cvss.CvssScoringVector, old.Cvss.Status,
				new.Cvss.CvssBaseScore, new.Cvss.CvssScoringVector, new.Cvss.Status)
		}
	}

	if config.Cvss3 {
		if !reflect.DeepEqual(old.Cvss3, new.Cvss3) {
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
				old.Cvss3.Cvss3BaseScore, old.Cvss3.Cvss3ScoringVector, old.Cvss3.Status,
				new.Cvss3.Cvss3BaseScore, new.Cvss3.Cvss3ScoringVector, new.Cvss3.Status)
		}
	}

	if config.AffectedRelease && (len(old.AffectedRelease) > 0 || len(new.AffectedRelease) > 0) {
		oldAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, old := range old.AffectedRelease {
			oldAffectedRelease[old.ProductName+"#"+old.Package] = old
		}

		newAffectedRelease := map[string]models.RedhatAffectedRelease{}
		for _, new := range new.AffectedRelease {
			newAffectedRelease[new.ProductName+"#"+new.Package] = new
		}

		for key, new := range newAffectedRelease {
			isNew := false

			old, ok := oldAffectedRelease[key]
			if ok {
				if !reflect.DeepEqual(old, new) {
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
				old.ProductName, old.Advisory, old.Package, old.Cpe, old.ReleaseDate,
				new.ProductName, new.Advisory, new.Package, new.Cpe, new.ReleaseDate)
		}
	}

	if config.PackageState && (len(old.PackageState) > 0 || len(new.PackageState) > 0) {
		oldPackageState := map[string]models.RedhatPackageState{}
		for _, old := range old.PackageState {
			oldPackageState[old.ProductName+"#"+old.PackageName] = old
		}

		newPackageState := map[string]models.RedhatPackageState{}
		for _, new := range new.PackageState {
			newPackageState[new.ProductName+"#"+new.PackageName] = new
		}

		for key, new := range newPackageState {
			isNew := false

			old, ok := oldPackageState[key]
			if ok {
				if !reflect.DeepEqual(old, new) {
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
				old.ProductName, old.FixState, old.PackageName,
				new.ProductName, new.FixState, new.PackageName)
		}

	}

	if config.Reference && (len(old.References) > 0 || len(new.References) > 0) {
		if !reflect.DeepEqual(old.References, new.References) {
			o := []string{}
			for _, old := range old.References {
				o = append(o, old.Reference)
			}

			n := []string{}
			for _, new := range new.References {
				n = append(o, new.Reference)
			}
			body += fmt.Sprintf(`
Reference
------------------
[old]
%s

[new]
%s
`,
				strings.Join(o, "\n"), strings.Join(n, "\n"))
			return
		}
	}

	if config.Details && (len(old.Details) > 0 || len(new.Details) > 0) {
		if !reflect.DeepEqual(old.Details, new.Details) {
			o := []string{}
			for _, old := range old.Details {
				o = append(o, old.Detail)
			}

			n := []string{}
			for _, new := range new.Details {
				n = append(n, new.Detail)
			}

			body += fmt.Sprintf(`
Detail
------------------
[old]
%s

[new]
%s
`,
				strings.Join(o, "\n"), strings.Join(n, "\n"))
			return
		}
	}

	return body

}
