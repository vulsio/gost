package db

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/knqyf263/gost/models"
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
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
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

	return nil
}
