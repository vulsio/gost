package db

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis"
	"github.com/knqyf263/gost/log"
	"github.com/knqyf263/gost/models"
	"gopkg.in/cheggaaa/pb.v1"
)

/**
# Redis Data Structure

- HASH
  ┌───┬────────────┬──────────┬──────────┬─────────────────────────────────┐
  │NO │    HASH    │  FIELD   │  VALUE   │             PURPOSE             │
  └───┴────────────┴──────────┴──────────┴─────────────────────────────────┘
  ┌───┬────────────┬──────────┬──────────┬─────────────────────────────────┐
  │ 1 │ CVE#$CVEID │  RedHat  │ $CVEJSON │     TO GET CVEJSON BY CVEID     │
  └───┴────────────┴──────────┴──────────┴─────────────────────────────────┘

**/

const (
	dialectRedis  = "redis"
	hashKeyPrefix = "CVE#"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// Name return db name
func (r *RedisDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (err error) {
	if err = r.connectRedis(dbPath); err != nil {
		err = fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	return
}

func (r *RedisDriver) connectRedis(dbPath string) error {
	var err error
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log.Error(err)
		return err
	}
	r.conn = redis.NewClient(option)
	err = r.conn.Ping().Err()
	return err
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

func (r *RedisDriver) GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error) {
	return nil, nil
}
func (r *RedisDriver) GetRedhat(cveID string) *models.RedhatCVE {
	result := r.conn.HGetAll(hashKeyPrefix + cveID)
	if result.Err() != nil {
		log.Error(result.Err())
		return nil
	}

	var redhat models.RedhatCVE
	if j, ok := result.Val()["RedHat"]; ok {
		if err := json.Unmarshal([]byte(j), &redhat); err != nil {
			log.Errorf("Failed to Unmarshal json. err : %s", err)
			return nil
		}
	}
	return &redhat
}

func (r *RedisDriver) GetRedhatMulti(cveIDs []string) map[string]*models.RedhatCVE {
	results := map[string]*models.RedhatCVE{}
	rs := map[string]*redis.StringStringMapCmd{}

	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		rs[cveID] = pipe.HGetAll(hashKeyPrefix + cveID)
	}
	if _, err := pipe.Exec(); err != nil {
		if err != redis.Nil {
			log.Errorf("Failed to get multi cve json. err : %s", err)
			return nil
		}
	}

	for cveID, result := range rs {
		var redhat models.RedhatCVE
		if j, ok := result.Val()["RedHat"]; ok {
			if err := json.Unmarshal([]byte(j), &redhat); err != nil {
				log.Errorf("Failed to Unmarshal json. err : %s", err)
				return nil
			}
		}
		results[cveID] = &redhat
	}
	return results
}

func (r *RedisDriver) GetDebian(string) *models.DebianCVE {
	return nil
}
func (r *RedisDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	cves, err := ConvertRedhat(cveJSONs)
	if err != nil {
		return err
	}
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		var pipe redis.Pipeliner
		pipe = r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if result := pipe.HSet(hashKeyPrefix+cve.Name, "RedHat", string(j)); result.Err() != nil {
			return fmt.Errorf("Failed to HSet CVE. err: %s", result.Err())
		}

		if _, err = pipe.Exec(); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()

	return nil
}

func (r *RedisDriver) InsertDebian(models.DebianJSON) error {
	return nil
}
