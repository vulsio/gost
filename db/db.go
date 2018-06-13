package db

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/spf13/viper"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) error
	MigrateDB() error
	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	//TODO return error
	// GetAllDebian() *[]models.DebianCVE
	GetRedhat(string) *models.RedhatCVE
	//TODO return error
	GetRedhatMulti([]string) map[string]*models.RedhatCVE
	//TODO return error
	GetDebian(string) *models.DebianCVE

	GetUnfixedCvesRedhat(string, string) (map[string]*models.RedhatCVE, error)

	//TODO return error
	InsertRedhat([]models.RedhatCVEJSON) error
	//TODO return error
	InsertDebian(models.DebianJSON) error
}

// NewDB return DB accessor.
func NewDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect. err: %s", dbType)
}

func InitDB(dbType string, dbPath string, debugSql bool) (driver DB, err error) {
	if driver, err = NewDB(viper.GetString("dbtype")); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, err
	}

	log15.Info("Opening DB.", "db", driver.Name())
	if err := driver.OpenDB(viper.GetString("dbtype"), viper.GetString("dbpath"), debugSql); err != nil {
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
