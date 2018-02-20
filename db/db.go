package db

import (
	"fmt"
	"time"

	"github.com/knqyf263/gost/log"
	"github.com/knqyf263/gost/models"
	"github.com/spf13/viper"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) error
	MigrateDB() error
	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	// GetAllDebian() *[]models.DebianCVE
	GetRedhat(string) *models.RedhatCVE
	GetRedhatMulti([]string) map[string]*models.RedhatCVE
	GetDebian(string) *models.DebianCVE
	InsertRedhat([]models.RedhatCVEJSON) error
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
		log.Error(err)
		return driver, err
	}

	log.Infof("Opening DB (%s)", driver.Name())
	if err := driver.OpenDB(viper.GetString("dbtype"), viper.GetString("dbpath"), debugSql); err != nil {
		log.Error(err)
		return driver, err
	}

	log.Infof("Migrating DB (%s)", driver.Name())
	if err := driver.MigrateDB(); err != nil {
		log.Error(err)
		return driver, err
	}
	return driver, nil
}
