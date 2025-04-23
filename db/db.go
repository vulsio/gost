package db

import (
	"fmt"
	"iter"
	"time"

	"golang.org/x/xerrors"

	"github.com/vulsio/gost/models"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool, Option) error
	CloseDB() error
	MigrateDB() error

	IsGostModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	GetRedhat(string) (*models.RedhatCVE, error)
	GetRedhatMulti([]string) (map[string]models.RedhatCVE, error)
	GetUnfixedCvesRedhat(string, string, bool) (map[string]models.RedhatCVE, error)
	GetAdvisoriesRedHat() (map[string][]string, error)
	GetDebian(string) (*models.DebianCVE, error)
	GetDebianMulti([]string) (map[string]models.DebianCVE, error)
	GetFixedCvesDebian(string, string) (map[string]models.DebianCVE, error)
	GetUnfixedCvesDebian(string, string) (map[string]models.DebianCVE, error)
	GetUbuntu(string) (*models.UbuntuCVE, error)
	GetUbuntuMulti([]string) (map[string]models.UbuntuCVE, error)
	GetFixedCvesUbuntu(string, string) (map[string]models.UbuntuCVE, error)
	GetUnfixedCvesUbuntu(string, string) (map[string]models.UbuntuCVE, error)
	GetAdvisoriesUbuntu() (map[string][]string, error)
	GetMicrosoft(string) (*models.MicrosoftCVE, error)
	GetMicrosoftMulti([]string) (map[string]models.MicrosoftCVE, error)
	GetExpandKB([]string, []string) ([]string, []string, error)
	GetRelatedProducts(string, []string) ([]string, error)
	GetFilteredCvesMicrosoft([]string, []string) (map[string]models.MicrosoftCVE, error)
	GetAdvisoriesMicrosoft() (map[string][]string, error)
	GetArch(string) (*models.ArchADV, error)
	GetArchMulti([]string) (map[string]models.ArchADV, error)
	GetFixedAdvsArch(string) (map[string]models.ArchADV, error)
	GetUnfixedAdvsArch(string) (map[string]models.ArchADV, error)
	GetAdvisoriesArch() (map[string][]string, error)

	InsertRedhat(iter.Seq2[models.RedhatCVE, error]) error
	InsertDebian([]models.DebianCVE) error
	InsertUbuntu(iter.Seq2[models.UbuntuCVE, error]) error
	InsertMicrosoft([]models.MicrosoftCVE, []models.MicrosoftKBRelation) error
	InsertArch([]models.ArchADV) error
}

// Option :
type Option struct {
	RedisTimeout time.Duration
}

// NewDB returns db driver
func NewDB(dbType, dbPath string, debugSQL bool, option Option) (driver DB, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, xerrors.Errorf("Failed to new db. err: %w", err)
	}

	if err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
		return nil, xerrors.Errorf("Failed to open db. err: %w", err)
	}

	isV1, err := driver.IsGostModelV1()
	if err != nil {
		return nil, xerrors.Errorf("Failed to IsGostModelV1. err: %w", err)
	}
	if isV1 {
		return nil, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, xerrors.Errorf("Failed to migrate db. err: %w", err)
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
	return nil, fmt.Errorf("Invalid database dialect. dbType: %s", dbType)
}
