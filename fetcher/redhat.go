package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/git"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

const (
	repoURL   = "https://github.com/aquasecurity/vuln-list-update.git"
	redhatDir = "redhat"
)

// FetchRedHatVulnList clones vuln-list and returns CVE JSONs
func FetchRedHatVulnList() (entries []models.RedhatCVEJSON, err error) {
	// Clone vuln-list repository
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(repoURL, dir, redhatDir)
	if err != nil {
		return nil, xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil, nil
	}

	rootDir := filepath.Join(dir, redhatDir)
	targets, err := util.FilterTargets(redhatDir, updatedFiles)
	if err != nil {
		return nil, xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log15.Debug("Red Hat: no updated file")
		return nil, nil
	}
	log15.Debug(fmt.Sprintf("Red Hat updated files: %d", len(targets)))

	var cves []RedhatCVE
	err = util.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		content, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		cve := RedhatCVE{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}
		switch cve.TempAffectedRelease.(type) {
		case []interface{}:
			var ar RedhatCVEAffectedReleaseArray
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = ar.AffectedRelease
		case map[string]interface{}:
			var ar RedhatCVEAffectedReleaseObject
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = []RedhatAffectedRelease{ar.AffectedRelease}
		case nil:
		default:
			return xerrors.New("unknown affected_release type")
		}

		switch cve.TempPackageState.(type) {
		case []interface{}:
			var ps RedhatCVEPackageStateArray
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = ps.PackageState
		case map[string]interface{}:
			var ps RedhatCVEPackageStateObject
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = []RedhatPackageState{ps.PackageState}
		case nil:
		default:
			return xerrors.New("unknown package_state type")
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in RedHat walk: %w", err)
	}

	for _, c := range cves {
		bugzilla := models.RedhatBugzilla{
			Description: c.Bugzilla.Description,
			BugzillaID:  c.Bugzilla.BugzillaID,
			URL:         c.Bugzilla.URL,
		}

		cvss := models.RedhatCvss{
			CvssBaseScore:     c.Cvss.CvssBaseScore,
			CvssScoringVector: c.Cvss.CvssScoringVector,
			Status:            c.Cvss.Status,
		}

		cvss3 := models.RedhatCvss3{
			Cvss3BaseScore:     c.Cvss3.Cvss3BaseScore,
			Cvss3ScoringVector: c.Cvss3.Cvss3ScoringVector,
			Status:             c.Cvss3.Status,
		}

		releases := []models.RedhatAffectedRelease{}
		for _, affected := range c.AffectedRelease {
			releases = append(releases, models.RedhatAffectedRelease{
				ProductName: affected.ProductName,
				ReleaseDate: affected.ReleaseDate,
				Advisory:    affected.Advisory,
				Package:     affected.Package,
				Cpe:         affected.Cpe,
			})
		}

		states := []models.RedhatPackageState{}
		for _, state := range c.PackageState {
			states = append(states, models.RedhatPackageState{
				ProductName: state.ProductName,
				FixState:    state.FixState,
				PackageName: state.PackageName,
				Cpe:         state.Cpe,
			})
		}

		entries = append(entries, models.RedhatCVEJSON{
			ThreatSeverity:       c.ThreatSeverity,
			PublicDate:           c.PublicDate,
			Bugzilla:             bugzilla,
			Cvss:                 cvss,
			Cvss3:                cvss3,
			Iava:                 c.Iava,
			Cwe:                  c.Cwe,
			Statement:            c.Statement,
			Acknowledgement:      c.Acknowledgement,
			Mitigation:           c.Mitigation,
			TempAffectedRelease:  c.TempAffectedRelease,
			AffectedRelease:      releases,
			PackageState:         states,
			Name:                 c.Name,
			DocumentDistribution: c.DocumentDistribution,
			Details:              c.Details,
			References:           c.References,
		})
	}
	return entries, nil
}

// RedhatCVE :
type RedhatCVE struct {
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

	Details    []string `json:"details"`
	References []string `json:"references"`
}

// RedhatCVEAffectedReleaseArray :
type RedhatCVEAffectedReleaseArray struct {
	AffectedRelease []RedhatAffectedRelease `json:"affected_release"`
}

// RedhatCVEAffectedReleaseObject :
type RedhatCVEAffectedReleaseObject struct {
	AffectedRelease RedhatAffectedRelease `json:"affected_release"`
}

// RedhatCVEPackageStateArray :
type RedhatCVEPackageStateArray struct {
	PackageState []RedhatPackageState `json:"package_state"`
}

// RedhatCVEPackageStateObject :
type RedhatCVEPackageStateObject struct {
	PackageState RedhatPackageState `json:"package_state"`
}

// RedhatDetail :
type RedhatDetail struct {
	Detail string `sql:"type:text"`
}

// RedhatReference :
type RedhatReference struct {
	Reference string `sql:"type:text"`
}

// RedhatBugzilla :
type RedhatBugzilla struct {
	Description string `json:"description" sql:"type:text"`
	BugzillaID  string `json:"id"`
	URL         string `json:"url"`
}

// RedhatCvss :
type RedhatCvss struct {
	CvssBaseScore     string `json:"cvss_base_score"`
	CvssScoringVector string `json:"cvss_scoring_vector"`
	Status            string `json:"status"`
}

// RedhatCvss3 :
type RedhatCvss3 struct {
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Status             string `json:"status"`
}

// RedhatAffectedRelease :
type RedhatAffectedRelease struct {
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	Cpe         string `json:"cpe"`
}

// RedhatPackageState :
type RedhatPackageState struct {
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	Cpe         string `json:"cpe"`
}
