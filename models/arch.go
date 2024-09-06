package models

// ArchADVJSON :
type ArchADVJSON struct {
	Advisories []string `json:"advisories"`
	Affected   string   `json:"affected"`
	Fixed      *string  `json:"fixed"`
	Issues     []string `json:"issues"`
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"`
	Ticket     *string  `json:"ticket"`
	Type       string   `json:"type"`
}

// ArchADV :
type ArchADV struct {
	ID         int64          `json:"-"`
	Name       string         `json:"name" gorm:"type:varchar(255)"`
	Packages   []ArchPackage  `json:"packages"`
	Status     string         `json:"status" gorm:"type:varchar(255)"`
	Severity   string         `json:"severity" gorm:"type:varchar(255)"`
	Type       string         `json:"type" gorm:"type:varchar(255)"`
	Affected   string         `json:"affected" gorm:"type:varchar(255)"`
	Fixed      *string        `json:"fixed" gorm:"type:varchar(255)"`
	Ticket     *string        `json:"ticket" gorm:"type:varchar(255)"`
	Issues     []ArchIssue    `json:"issues"`
	Advisories []ArchAdvisory `json:"advisories"`
}

// ArchPackage :
type ArchPackage struct {
	ID        int64  `json:"-"`
	ArchADVID int64  `json:"-"`
	Name      string `json:"name" gorm:"type:varchar(255);index:idx_arch_packages_name"`
}

// ArchIssue :
type ArchIssue struct {
	ID        int64  `json:"-"`
	ArchADVID int64  `json:"-"`
	Issue     string `json:"issue" gorm:"type:varchar(255);index:idx_arch_issues_issue"`
}

// ArchAdvisory :
type ArchAdvisory struct {
	ID        int64  `json:"-"`
	ArchADVID int64  `json:"-"`
	Advisory  string `json:"advisory" gorm:"type:varchar(255)"`
}

// ConvertArch :
func ConvertArch(advJSONs []ArchADVJSON) []ArchADV {
	advs := make([]ArchADV, 0, len(advJSONs))
	for _, aj := range advJSONs {
		advs = append(advs, ArchADV{
			Name: aj.Name,
			Packages: func() []ArchPackage {
				ps := make([]ArchPackage, 0, len(aj.Packages))
				for _, p := range aj.Packages {
					ps = append(ps, ArchPackage{Name: p})
				}
				return ps
			}(),
			Status:   aj.Status,
			Severity: aj.Severity,
			Type:     aj.Type,
			Affected: aj.Affected,
			Fixed:    aj.Fixed,
			Ticket:   aj.Ticket,
			Issues: func() []ArchIssue {
				is := make([]ArchIssue, 0, len(aj.Issues))
				for _, i := range aj.Issues {
					is = append(is, ArchIssue{Issue: i})
				}
				return is
			}(),
			Advisories: func() []ArchAdvisory {
				as := make([]ArchAdvisory, 0, len(aj.Advisories))
				for _, a := range aj.Advisories {
					as = append(as, ArchAdvisory{Advisory: a})
				}
				return as
			}(),
		})
	}
	return advs
}
