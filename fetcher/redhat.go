package fetcher

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/git"
	trivyUtils "github.com/aquasecurity/trivy/pkg/utils"
	types "github.com/aquasecurity/trivy/pkg/vulnsrc/redhat"
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"golang.org/x/xerrors"
)

const (
	repoURL   = "https://github.com/aquasecurity/vuln-list.git"
	redhatDir = "redhat"
)

func FetchRedHatVulnList() (entries []models.RedhatCVEJSON, err error) {
	// Clone vuln-list repository
	dir := filepath.Join(trivyUtils.CacheDir(), "vuln-list")
	updatedFiles, err := git.CloneOrPull(repoURL, dir)
	if err != nil {
		return nil, xerrors.Errorf("error in vulnsrc clone or pull: %w", err)
	}
	log15.Debug("Failed to fetch the CVE details.", "err", err)

	// Only last_updated.json
	if len(updatedFiles) <= 1 {
		return nil, nil
	}

	rootDir := filepath.Join(dir, redhatDir)
	targets, err := trivyUtils.FilterTargets(redhatDir, updatedFiles)
	if err != nil {
		return nil, xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log15.Debug("Red Hat: no updated file")
		return nil, nil
	}
	log15.Debug("Red Hat updated files: %d", len(targets))

	var cves []types.RedhatCVE
	err = trivyUtils.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		content, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		cve := types.RedhatCVE{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}
		switch cve.TempAffectedRelease.(type) {
		case []interface{}:
			var ar types.RedhatCVEAffectedReleaseArray
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = ar.AffectedRelease
		case map[string]interface{}:
			var ar types.RedhatCVEAffectedReleaseObject
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = []types.RedhatAffectedRelease{ar.AffectedRelease}
		case nil:
		default:
			return xerrors.New("unknown affected_release type")
		}

		switch cve.TempPackageState.(type) {
		case []interface{}:
			var ps types.RedhatCVEPackageStateArray
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = ps.PackageState
		case map[string]interface{}:
			var ps types.RedhatCVEPackageStateObject
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = []types.RedhatPackageState{ps.PackageState}
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
