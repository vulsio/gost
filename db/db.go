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
	OpenDB(string, string, bool) (bool, error)
	MigrateDB() error

	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	GetRedhat(string) *models.RedhatCVE
	GetRedhatMulti([]string) map[string]models.RedhatCVE
	GetDebian(string) *models.DebianCVE
	GetMicrosoft(string) *models.MicrosoftCVE
	GetMicrosoftMulti([]string) map[string]models.MicrosoftCVE
	GetUnfixedCvesRedhat(string, string, bool) map[string]models.RedhatCVE
	GetUnfixedCvesDebian(string, string) map[string]models.DebianCVE

	InsertRedhat([]models.RedhatCVEJSON) error
	InsertDebian(models.DebianJSON) error
	InsertMicrosoft([]models.MicrosoftXML, []models.MicrosoftBulletinSearch) error
}

// NewDB returns db driver
func NewDB(dbType, dbPath string, debugSQL bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, false, err
	}

	log15.Info("Opening DB.", "db", driver.Name())
	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	log15.Info("Migrating DB.", "db", driver.Name())
	if err := driver.MigrateDB(); err != nil {
		log15.Error("Failed to migrate db.", "err", err)
		return driver, false, err
	}
	return driver, false, nil
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
