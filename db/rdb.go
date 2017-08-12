package db

import (
	"fmt"

	pb "gopkg.in/cheggaaa/pb.v1"

	"github.com/jinzhu/gorm"
	"github.com/knqyf263/go-security-tracker/models"
	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	// Required SQLite3.
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Supported DB dialects.
const (
	dialectSqlite3    = "sqlite3"
	dialectMysql      = "mysql"
	dialectPostgreSQL = "postgres"
)

// RDBDriver is Driver for RDB
type RDBDriver struct {
	name string
	conn *gorm.DB
}

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool) (err error) {
	r.conn, err = gorm.Open(dbType, dbPath)
	if err != nil {
		err = fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
		return
	}
	r.conn.LogMode(debugSQL)
	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
		r.conn.Exec("PRAGMA journal_mode=WAL;")
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.RedhatCVE{},
		&models.Detail{},
		&models.Reference{},
		&models.Bugzilla{},
		&models.Cvss{},
		&models.Cvss3{},
		&models.AffectedRelease{},
		&models.PackageState{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	return nil
}

func (r *RDBDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	cves := convertRedhat(cveJSONs)
	bar := pb.StartNew(len(cves))
	for _, cve := range cves {
		r.conn.Save(&cve)
		bar.Increment()
	}
	bar.Finish()
	return err

}

func convertRedhat(cveJSONs []models.RedhatCVEJSON) (cves []models.RedhatCVE) {
	for _, cve := range cveJSONs {
		var details []models.Detail
		for _, d := range cve.Details {
			details = append(details, models.Detail{Detail: d})
		}

		var references []models.Reference
		for _, r := range cve.References {
			references = append(references, models.Reference{Reference: r})
		}

		// TODO: more efficient
		c := models.RedhatCVE{
			ThreatSeverity:       cve.ThreatSeverity,
			PublicDate:           cve.PublicDate,
			Bugzilla:             cve.Bugzilla,
			Cvss:                 cve.Cvss,
			Cvss3:                cve.Cvss3,
			Iava:                 cve.Iava,
			Cwe:                  cve.Cwe,
			Statement:            cve.Statement,
			Acknowledgement:      cve.Acknowledgement,
			Mitigation:           cve.Mitigation,
			AffectedRelease:      cve.AffectedRelease,
			PackageState:         cve.PackageState,
			Name:                 cve.Name,
			DocumentDistribution: cve.DocumentDistribution,

			Details:    details,
			References: references,
		}
		cves = append(cves, c)
	}
	return cves
}
