package db

import (
	"fmt"

	"github.com/knqyf263/go-security-tracker/log"
	"github.com/knqyf263/go-security-tracker/models"
	"github.com/spf13/viper"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) error
	MigrateDB() error
	GetRedhat(string) *models.RedhatCVE
	// GetByCpeName(string) []*models.RedhatCVE
	InsertRedhat([]models.RedhatCVEJSON) error
}

// NewDB return DB accessor.
func NewDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect, %s", dbType)
}

func InitDB(dbType string, dbPath string, debugSql bool) (driver DB, err error) {
	if driver, err = NewDB(viper.GetString("dbtype")); err != nil {
		log.Error(err)
		return driver, err
	}

	log.Infof("Opening DB (%s).", driver.Name())
	if err := driver.OpenDB(viper.GetString("dbtype"), viper.GetString("dbpath"), debugSql); err != nil {
		log.Error(err)
		return driver, err
	}

	log.Infof("Migrating DB (%s).", driver.Name())
	if err := driver.MigrateDB(); err != nil {
		log.Error(err)
		return driver, err
	}
	return driver, nil
}
