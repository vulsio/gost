package db

import (
	"fmt"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/gost/models"
	"golang.org/x/xerrors"
)

// DB is interface for a database driver
type DB interface {
	Name() string
	OpenDB(string, string, bool, Option) (bool, error)
	CloseDB() error
	MigrateDB() error

	IsGostModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error)
	GetRedhat(string) (*models.RedhatCVE, error)
	GetRedhatMulti([]string) (map[string]models.RedhatCVE, error)
	GetDebian(string) (*models.DebianCVE, error)
	GetDebianMulti([]string) (map[string]models.DebianCVE, error)
	GetUbuntu(string) (*models.UbuntuCVE, error)
	GetUbuntuMulti([]string) (map[string]models.UbuntuCVE, error)
	GetCveIDsByMicrosoftKBID(kbID string) ([]string, error)
	GetMicrosoft(string) (*models.MicrosoftCVE, error)
	GetMicrosoftMulti([]string) (map[string]models.MicrosoftCVE, error)
	GetUnfixedCvesRedhat(string, string, bool) (map[string]models.RedhatCVE, error)
	GetUnfixedCvesDebian(string, string) (map[string]models.DebianCVE, error)
	GetFixedCvesDebian(string, string) (map[string]models.DebianCVE, error)
	GetUnfixedCvesUbuntu(string, string) (map[string]models.UbuntuCVE, error)
	GetFixedCvesUbuntu(string, string) (map[string]models.UbuntuCVE, error)

	InsertRedhat([]models.RedhatCVE) error
	InsertDebian([]models.DebianCVE) error
	InsertUbuntu([]models.UbuntuCVE) error
	InsertMicrosoft([]models.MicrosoftCVE, []models.MicrosoftProduct) error
}

type Option struct {
	RedisTimeout time.Duration
}

// NewDB returns db driver
func NewDB(dbType, dbPath string, debugSQL bool, option Option) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		log15.Error("Failed to new db.", "err", err)
		return driver, false, err
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
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
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect. dbType: %s", dbType)
}

// IndexChunk has a starting point and an ending point for Chunk
type IndexChunk struct {
	From, To int
}

func chunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}
