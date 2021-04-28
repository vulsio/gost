package db

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/knqyf263/gost/models"
	"github.com/knqyf263/gost/util"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/xerrors"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	// Required MySQL.  See https://gorm.io/docs/connecting_to_the_database.html
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"

	// Required SQLite3.
	"gorm.io/driver/sqlite"
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
	defaultGormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold:             time.Second,   // Slow SQL threshold
				LogLevel:                  logger.Silent, // Log level
				IgnoreRecordNotFoundError: true,          // Ignore ErrRecordNotFound error for logger
			},
		)}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &defaultGormConfig)
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &defaultGormConfig)
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &defaultGormConfig)
	default:
		err = xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}

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

	if debugSQL {
		r.conn.Logger.LogMode(logger.Info)
	}
	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if sqlDB, err := r.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	} else {
		if err = sqlDB.Close(); err != nil {
			return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
		}
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

		&models.MicrosoftCVE{},
		&models.MicrosoftProductStatus{},
		&models.MicrosoftThreat{},
		&models.MicrosoftRemediation{},
		&models.MicrosoftReference{},
		&models.MicrosoftScoreSet{},
		&models.MicrosoftCveID{},
		&models.MicrosoftProduct{},
		&models.MicrosoftKBID{},
	); err != nil {
		return xerrors.Errorf("Failed to migrate. err: %w", err)
	}

	var errs util.Errors
	// redhat_cve
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatCVE{}, "idx_redhat_cves_name"))

	// redhat_details
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatDetail{}, "idx_redhat_details_redhat_cve_id"))

	// redhat_references
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatReference{}, "idx_redhat_references_redhat_cve_id"))

	// redhat_bugzillas
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatBugzilla{}, "idx_redhat_bugzillas_redhat_cve_id"))

	// redhat_cvsses
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatCvss{}, "idx_redhat_cvsses_redhat_cve_id"))

	// redhat_cvss3
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatCvss3{}, "idx_redhat_cvss3_redhat_cve_id"))

	// redhat_affected_releases
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatAffectedRelease{}, "idx_redhat_affected_releases_redhat_cve_id"))

	// redhat_package_states
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatPackageState{}, "idx_redhat_package_states_redhat_cve_id"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatPackageState{}, "idx_redhat_package_states_cpe"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatPackageState{}, "idx_redhat_package_states_package_name"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.RedhatPackageState{}, "idx_redhat_package_states_fix_state"))

	// debian_cves
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianCVE{}, "idx_debian_cves_cveid"))

	// debian_packages
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianPackage{}, "idx_debian_pacakges_debian_cve_id"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianPackage{}, "idx_debian_pacakges_package_name"))

	// debian_releases
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianRelease{}, "idx_debian_releases_debian_package_id"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianRelease{}, "idx_debian_releases_product_name"))
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.DebianRelease{}, "idx_debian_releases_status"))

	// microsoft_cves
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftCVE{}, "idx_microsoft_cves_cveid"))
	// microsoft_reference
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftReference{}, "idx_microsoft_reference_microsoft_cve_id"))
	// microsoft_kb_id
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftKBID{}, "idx_microsoft_kb_id_microsoft_cve_id"))
	// microsoft_product_status
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftProductStatus{}, "idx_microsoft_product_status_microsoft_cve_id"))
	// microsoft_threat
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftThreat{}, "idx_microsoft_threat_microsoft_cve_id"))
	// microsoft_remediation
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftRemediation{}, "idx_microsoft_remediation_microsoft_cve_id"))
	// microsoft_score_set
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftScoreSet{}, "idx_microsoft_score_set_microsoft_cve_id"))
	// microsoft_product
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftProduct{}, "idx_microsoft_product_microsoft_cve_id"))
	// microsoft_cve_id
	errs = errs.Add(r.conn.Migrator().CreateIndex(&models.MicrosoftCveID{}, "idx_microsoft_cve_id_microsoft_cve_id"))

	return nil
}
