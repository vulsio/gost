package db

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/models"
	"golang.org/x/xerrors"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool) (bool, error)
	CloseDB() error
	MigrateDB() error

	IsGostModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	GetRedhat(string) *models.RedhatCVE
	GetRedhatMulti([]string) map[string]models.RedhatCVE
	GetDebian(string) *models.DebianCVE
	GetUbuntu(string) *models.UbuntuCVE
	GetMicrosoft(string) *models.MicrosoftCVE
	GetMicrosoftMulti([]string) map[string]models.MicrosoftCVE
	GetUnfixedCvesRedhat(string, string, bool) map[string]models.RedhatCVE
	GetUnfixedCvesDebian(string, string) map[string]models.DebianCVE
	GetFixedCvesDebian(string, string) map[string]models.DebianCVE
	GetUnfixedCvesUbuntu(string, string) map[string]models.UbuntuCVE
	GetFixedCvesUbuntu(string, string) map[string]models.UbuntuCVE

	InsertRedhat([]models.RedhatCVEJSON) error
	InsertDebian(models.DebianJSON) error
	InsertUbuntu([]models.UbuntuCVEJSON) error
	InsertMicrosoft([]models.MicrosoftXML, []models.MicrosoftBulletinSearch) error
}

// NewDB returns db driver
func NewDB(dbType, dbPath string, debugSQL bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, false, err
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	isV1, err := driver.IsGostModelV1()
	if err != nil {
		log15.Error("Failed to IsGostModelV1.", "err", err)
		return nil, false, err
	}
	if isV1 {
		log15.Error("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again")
		return nil, false, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		log15.Error("Failed to migrate db.", "err", err)
		return driver, false, err
	}
	return driver, false, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType, batchSize: viper.GetInt("batch-size")}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect. err: %s", dbType)
}
