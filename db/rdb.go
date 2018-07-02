package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/knqyf263/gost/models"
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

	return nil
}
