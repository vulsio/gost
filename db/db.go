package db

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) error
	MigrateDB() error

	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	GetRedhat(string) *models.RedhatCVE
	GetRedhatMulti([]string) map[string]models.RedhatCVE
	GetDebian(string) *models.DebianCVE
	GetUnfixedCvesRedhat(string, string) map[string]models.RedhatCVE
	GetUnfixedCvesDebian(string, string) map[string]models.DebianCVE

	InsertRedhat([]models.RedhatCVEJSON) error
	InsertDebian(models.DebianJSON) error
}

// NewDB returns db driver
//TODO DBURL
func NewDB(dbType, dbPath string, debugSQL bool) (driver DB, err error) {
	if driver, err = newDB(dbType); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, err
	}

	log15.Info("Opening DB.", "db", driver.Name())
	if err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		log15.Error("Failed to open db.", "err", err)
		return driver, err
	}

	log15.Info("Migrating DB.", "db", driver.Name())
	if err := driver.MigrateDB(); err != nil {
		log15.Error("Failed to migrate db.", "err", err)
		return driver, err
	}
	return driver, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect. err: %s", dbType)
}
