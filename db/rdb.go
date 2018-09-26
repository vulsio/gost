package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
	sqlite3 "github.com/mattn/go-sqlite3"

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
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	r.conn, err = gorm.Open(dbType, dbPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, fmt.Errorf(msg)
			}
		}
		return false, fmt.Errorf(msg)
	}
	r.conn.LogMode(debugSQL)
	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	//TODO Add FetchMeta
	if err := r.conn.AutoMigrate(
		&models.RedhatCVE{},
		&models.RedhatDetail{},
		&models.RedhatReference{},
		&models.RedhatBugzilla{},
		&models.RedhatCvss{},
		&models.RedhatCvss3{},
		&models.RedhatAffectedRelease{},
		&models.RedhatPackageState{},

		&models.DebianCVE{},
		&models.DebianPackage{},
		&models.DebianRelease{},

		&models.MicrosoftCVE{},
		&models.MicrosoftProductStatus{},
		&models.MicrosoftThreat{},
		&models.MicrosoftRemediation{},
		&models.MicrosoftReference{},
		&models.MicrosoftScoreSet{},
		&models.MicrosoftCveID{},
		&models.MicrosoftProduct{},
		&models.MicrosoftKBID{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	var errs gorm.Errors
	// redhat_cve
	errs = errs.Add(r.conn.Model(&models.RedhatCVE{}).AddIndex("idx_redhat_cves_name", "name").Error)

	// redhat_details
	errs = errs.Add(r.conn.Model(&models.RedhatDetail{}).AddIndex("idx_redhat_details_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_references
	errs = errs.Add(r.conn.Model(&models.RedhatReference{}).AddIndex("idx_redhat_references_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_bugzillas
	errs = errs.Add(r.conn.Model(&models.RedhatBugzilla{}).AddIndex("idx_redhat_bugzillas_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_cvsses
	errs = errs.Add(r.conn.Model(&models.RedhatCvss{}).AddIndex("idx_redhat_cvsses_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_cvss3
	errs = errs.Add(r.conn.Model(&models.RedhatCvss3{}).AddIndex("idx_redhat_cvss3_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_affected_releases
	errs = errs.Add(r.conn.Model(&models.RedhatAffectedRelease{}).AddIndex("idx_redhat_affected_releases_redhat_cve_id", "redhat_cve_id").Error)

	// redhat_package_states
	errs = errs.Add(r.conn.Model(&models.RedhatPackageState{}).AddIndex("idx_redhat_package_states_redhat_cve_id", "redhat_cve_id").Error)
	errs = errs.Add(r.conn.Model(&models.RedhatPackageState{}).AddIndex("idx_redhat_package_states_cpe", "cpe").Error)
	errs = errs.Add(r.conn.Model(&models.RedhatPackageState{}).AddIndex("idx_redhat_package_states_package_name", "package_name").Error)
	errs = errs.Add(r.conn.Model(&models.RedhatPackageState{}).AddIndex("idx_redhat_package_states_fix_state", "fix_state").Error)

	// debian_cves
	errs = errs.Add(r.conn.Model(&models.DebianCVE{}).AddIndex("idx_debian_cves_cveid", "cve_id").Error)

	// debian_packages
	errs = errs.Add(r.conn.Model(&models.DebianPackage{}).AddIndex("idx_debian_pacakges_debian_cve_id", "debian_cve_id").Error)
	errs = errs.Add(r.conn.Model(&models.DebianPackage{}).AddIndex("idx_debian_pacakges_package_name", "package_name").Error)

	// debian_releases
	errs = errs.Add(r.conn.Model(&models.DebianRelease{}).AddIndex("idx_debian_releases_debian_package_id", "debian_package_id").Error)
	errs = errs.Add(r.conn.Model(&models.DebianRelease{}).AddIndex("idx_debian_releases_product_name", "product_name").Error)
	errs = errs.Add(r.conn.Model(&models.DebianRelease{}).AddIndex("idx_debian_releases_status", "status").Error)

	// microsoft_cves
	errs = errs.Add(r.conn.Model(&models.MicrosoftCVE{}).AddIndex("idx_microsoft_cves_cveid", "cve_id").Error)
	// microsoft_reference
	errs = errs.Add(r.conn.Model(&models.MicrosoftReference{}).AddIndex("idx_microsoft_reference_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_kb_id
	errs = errs.Add(r.conn.Model(&models.MicrosoftKBID{}).AddIndex("idx_microsoft_kb_id_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_product_status
	errs = errs.Add(r.conn.Model(&models.MicrosoftProductStatus{}).AddIndex("idx_microsoft_product_status_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_threat
	errs = errs.Add(r.conn.Model(&models.MicrosoftThreat{}).AddIndex("idx_microsoft_threat_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_remediation
	errs = errs.Add(r.conn.Model(&models.MicrosoftRemediation{}).AddIndex("idx_microsoft_remediation_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_score_set
	errs = errs.Add(r.conn.Model(&models.MicrosoftScoreSet{}).AddIndex("idx_microsoft_score_set_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_product
	errs = errs.Add(r.conn.Model(&models.MicrosoftProduct{}).AddIndex("idx_microsoft_product_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_kb_id
	errs = errs.Add(r.conn.Model(&models.MicrosoftKBID{}).AddIndex("idx_microsoft_kb_id_microsoft_cve_id", "microsoft_cve_id").Error)
	// microsoft_cve_id
	errs = errs.Add(r.conn.Model(&models.MicrosoftCveID{}).AddIndex("idx_microsoft_cve_id_microsoft_cve_id", "microsoft_cve_id").Error)

	return nil
}
