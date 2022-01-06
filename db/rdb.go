package db

import (
	"errors"
	"log"
	"os"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/vulsio/gost/config"
	"github.com/vulsio/gost/models"
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
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool, _ Option) (locked bool, err error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
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
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
			}
		}
		return false, xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
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
	sqlDB, err := r.conn.DB()
	if err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	return sqlDB.Close()
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.FetchMeta{},

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

		&models.UbuntuCVE{},
		&models.UbuntuReference{},
		&models.UbuntuNote{},
		&models.UbuntuBug{},
		&models.UbuntuPatch{},
		&models.UbuntuReleasePatch{},
		&models.UbuntuUpstream{},
		&models.UbuntuUpstreamLink{},

		&models.MicrosoftCVE{},
		&models.MicrosoftProductStatus{},
		&models.MicrosoftThreat{},
		&models.MicrosoftRemediation{},
		&models.MicrosoftReference{},
		&models.MicrosoftScoreSet{},
		&models.MicrosoftProduct{},
		&models.MicrosoftKBID{},
	); err != nil {
		return xerrors.Errorf("Failed to migrate. err: %w", err)
	}

	return nil
}

// IsGostModelV1 determines if the DB was created at the time of Gost Model v1
func (r *RDBDriver) IsGostModelV1() (bool, error) {
	if r.conn.Migrator().HasTable(&models.FetchMeta{}) {
		return false, nil
	}

	var (
		count int64
		err   error
	)
	switch r.name {
	case dialectSqlite3:
		err = r.conn.Table("sqlite_master").Where("type = ?", "table").Count(&count).Error
	case dialectMysql:
		err = r.conn.Table("information_schema.tables").Where("table_schema = ?", r.conn.Migrator().CurrentDatabase()).Count(&count).Error
	case dialectPostgreSQL:
		err = r.conn.Table("pg_tables").Where("schemaname = ?", "public").Count(&count).Error
	}

	if count > 0 {
		return true, nil
	}
	return false, err
}

// GetFetchMeta get FetchMeta from Database
func (r *RDBDriver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = r.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GostRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GostRevision = config.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}
