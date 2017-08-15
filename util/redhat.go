package util

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/knqyf263/gost/config"
	"github.com/knqyf263/gost/models"
)

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
		if reflect.DeepEqual(old.Bugzilla, new.Bugzilla) == false {
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
		if reflect.DeepEqual(old.Cvss, new.Cvss) == false {
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
		if reflect.DeepEqual(old.Cvss3, new.Cvss3) == false {
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
				if reflect.DeepEqual(old, new) == false {
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
				if reflect.DeepEqual(old, new) == false {
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
		if reflect.DeepEqual(old.References, new.References) == false {
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
		if reflect.DeepEqual(old.Details, new.Details) == false {
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
