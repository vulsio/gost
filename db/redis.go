package db

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis"
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/models"
	"github.com/labstack/gommon/log"
	"gopkg.in/cheggaaa/pb.v1"
)

/**
# Redis Data Structure

- HASH
  ┌───┬────────────┬───────────────────────────┬──────────┬─────────────────────────────────┐
  │NO │    HASH    │         FIELD             │  VALUE   │             PURPOSE             │
  └───┴────────────┴───────────────────────────┴──────────┴─────────────────────────────────┘
  ┌───┬────────────┬───────────────────────────┬──────────┬─────────────────────────────────┐
  │ 1 │CVE#$CVEID  │  RedHat/Debian/Microsoft  │ $CVEJSON │     TO GET CVEJSON BY CVEID     │
  └───┴────────────┴───────────────────────────┴──────────┴─────────────────────────────────┘


- ZINDE  X
  ┌───┬────────────────┬──────────┬────────────┬───────────────────────────────────────────┐
  │NO │    KEY         │  SCORE   │  MEMBER    │                PURPOSE                    │
  └───┴────────────────┴──────────┴────────────┴───────────────────────────────────────────┘
  ┌───┬────────────────┬──────────┬────────────┬───────────────────────────────────────────┐
  │ 1 │CVE#R#$PKGNAME  │    0     │  $CVEID    │(RedHat) GET RELATED []CVEID BY PKGNAME    │
  ├───┼────────────────┼──────────┼────────────┼───────────────────────────────────────────┤
  │ 2 │CVE#D#$PKGNAME  │    0     │  $CVEID    │(Debian) GET RELATED []CVEID BY PKGNAME    │
  ├───┼────────────────┼──────────┼────────────┼───────────────────────────────────────────┤
  │ 3 │CVE#K#$KBID     │    0     │  $CVEID    │(Microsoft) GET RELATED []CVEID BY KBID    │
  ├───┼────────────────┼──────────┼────────────┼───────────────────────────────────────────┤
  │ 4 │CVE#P#$PRODUCTID│    0     │$PRODUCTNAME│(Microsoft) GET RELATED []PRODUCTNAME BY ID│
  └───┴────────────────┴──────────┴────────────┴───────────────────────────────────────────┘

**/

const (
	dialectRedis                 = "redis"
	hashKeyPrefix                = "CVE#"
	zindRedHatPrefix             = "CVE#R#"
	zindDebianPrefix             = "CVE#D#"
	zindMicrosoftKBIDPrefix      = "CVE#K#"
	zindMicrosoftProductIDPrefix = "CVE#P#"
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
func (r *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	if err = r.connectRedis(dbPath); err != nil {
		err = fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	return
}

func (r *RedisDriver) connectRedis(dbPath string) error {
	var err error
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log15.Error("Failed to parse url.", "err", err)
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

// GetAfterTimeRedhat :
func (r *RedisDriver) GetAfterTimeRedhat(time.Time) ([]models.RedhatCVE, error) {
	return nil, fmt.Errorf("Not implemented yet")
}

// GetRedhat :
func (r *RedisDriver) GetRedhat(cveID string) *models.RedhatCVE {
	result := r.conn.HGetAll(hashKeyPrefix + cveID)
	if result.Err() != nil {
		log15.Error("Failed to get cve.", "err", result.Err())
		return nil
	}

	var redhat models.RedhatCVE
	if j, ok := result.Val()["RedHat"]; ok {
		if err := json.Unmarshal([]byte(j), &redhat); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
	}
	return &redhat
}

// GetRedhatMulti :
func (r *RedisDriver) GetRedhatMulti(cveIDs []string) map[string]models.RedhatCVE {
	results := map[string]models.RedhatCVE{}
	rs := map[string]*redis.StringStringMapCmd{}

	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		rs[cveID] = pipe.HGetAll(hashKeyPrefix + cveID)
	}
	if _, err := pipe.Exec(); err != nil {
		if err != redis.Nil {
			log15.Error("Failed to get multi cve json.", "err", err)
			return nil
		}
	}

	for cveID, result := range rs {
		var redhat models.RedhatCVE
		if j, ok := result.Val()["RedHat"]; ok {
			if err := json.Unmarshal([]byte(j), &redhat); err != nil {
				log15.Error("Failed to Unmarshal json.", "err", err)
				return nil
			}
		}
		results[cveID] = redhat
	}
	return results
}

// GetUnfixedCvesRedhat :
func (r *RedisDriver) GetUnfixedCvesRedhat(major, pkgName string, ignoreWillNotFix bool) (m map[string]models.RedhatCVE) {
	m = map[string]models.RedhatCVE{}

	var result *redis.StringSliceCmd
	if result = r.conn.ZRange(zindRedHatPrefix+pkgName, 0, -1); result.Err() != nil {
		log.Error(result.Err())
		return
	}

	cpe := fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", major)
	for _, cveID := range result.Val() {
		red := r.GetRedhat(cveID)
		if red == nil {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			continue
		}

		// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/index#cve_format
		pkgStats := []models.RedhatPackageState{}
		for _, pkgstat := range red.PackageState {
			if pkgstat.Cpe != cpe ||
				pkgstat.PackageName != pkgName ||
				pkgstat.FixState == "Not affected" ||
				pkgstat.FixState == "New" {
				continue

			} else if ignoreWillNotFix && pkgstat.FixState == "Will not fix" {
				continue
			}
			pkgStats = append(pkgStats, pkgstat)
		}
		if len(pkgStats) == 0 {
			continue
		}
		red.PackageState = pkgStats
		m[cveID] = *red
	}
	return
}

// GetUnfixedCvesDebian :
func (r *RedisDriver) GetUnfixedCvesDebian(major, pkgName string) (m map[string]models.DebianCVE) {
	m = map[string]models.DebianCVE{}
	codeName, ok := debVerCodename[major]
	if !ok {
		log15.Error("Not supported yet", "major", major)
		return
	}
	var result *redis.StringSliceCmd
	if result = r.conn.ZRange(zindDebianPrefix+pkgName, 0, -1); result.Err() != nil {
		log.Error(result.Err())
		return
	}

	for _, cveID := range result.Val() {
		deb := r.GetDebian(cveID)
		if deb == nil {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			continue
		}

		pkgs := []models.DebianPackage{}
		for _, pkg := range deb.Package {
			if pkg.PackageName != pkgName {
				continue
			}
			rels := []models.DebianRelease{}
			for _, rel := range pkg.Release {
				if rel.ProductName == codeName && rel.Status == "open" {
					rels = append(rels, rel)
				}
			}
			if len(rels) == 0 {
				continue
			}
			pkg.Release = rels
			pkgs = append(pkgs, pkg)
		}
		if len(pkgs) != 0 {
			deb.Package = pkgs
			m[cveID] = *deb
		}
	}
	return
}

// GetDebian :
func (r *RedisDriver) GetDebian(cveID string) *models.DebianCVE {
	var result *redis.StringStringMapCmd
	if result = r.conn.HGetAll(hashKeyPrefix + cveID); result.Err() != nil {
		log.Error(result.Err())
		return nil
	}
	deb := models.DebianCVE{}
	j, ok := result.Val()["Debian"]
	if !ok {
		return nil
	}

	if err := json.Unmarshal([]byte(j), &deb); err != nil {
		log.Errorf("Failed to Unmarshal json. err : %s", err)
		return nil
	}
	return &deb
}

// GetMicrosoft :
func (r *RedisDriver) GetMicrosoft(cveID string) *models.MicrosoftCVE {
	result := r.conn.HGetAll(hashKeyPrefix + cveID)
	if result.Err() != nil {
		log15.Error("Failed to get cve.", "err", result.Err())
		return nil
	}

	var ms models.MicrosoftCVE
	if j, ok := result.Val()["Microsoft"]; ok {
		if err := json.Unmarshal([]byte(j), &ms); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
	}
	return &ms
}

// GetMicrosoftMulti :
func (r *RedisDriver) GetMicrosoftMulti(cveIDs []string) map[string]models.MicrosoftCVE {
	results := map[string]models.MicrosoftCVE{}
	rs := map[string]*redis.StringStringMapCmd{}

	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		rs[cveID] = pipe.HGetAll(hashKeyPrefix + cveID)
	}
	if _, err := pipe.Exec(); err != nil {
		if err != redis.Nil {
			log15.Error("Failed to get multi cve json.", "err", err)
			return nil
		}
	}

	for cveID, result := range rs {
		var ms models.MicrosoftCVE
		if j, ok := result.Val()["Microsoft"]; ok {
			if err := json.Unmarshal([]byte(j), &ms); err != nil {
				log15.Error("Failed to Unmarshal json.", "err", err)
				return nil
			}
		}
		results[cveID] = ms
	}
	return results
}

//InsertRedhat :
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

		for _, pkg := range cve.PackageState {
			if result := pipe.ZAdd(
				zindRedHatPrefix+pkg.PackageName,
				redis.Z{Score: 0, Member: cve.Name},
			); result.Err() != nil {
				return fmt.Errorf("Failed to ZAdd pkg name. err: %s", result.Err())
			}
		}

		if _, err = pipe.Exec(); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()

	return nil
}

// InsertDebian :
func (r *RedisDriver) InsertDebian(cveJSONs models.DebianJSON) error {
	cves := ConvertDebian(cveJSONs)
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		var pipe redis.Pipeliner
		pipe = r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if result := pipe.HSet(hashKeyPrefix+cve.CveID, "Debian", string(j)); result.Err() != nil {
			return fmt.Errorf("Failed to HSet CVE. err: %s", result.Err())
		}

		for _, pkg := range cve.Package {
			if result := pipe.ZAdd(
				zindDebianPrefix+pkg.PackageName,
				redis.Z{Score: 0, Member: cve.CveID},
			); result.Err() != nil {
				return fmt.Errorf("Failed to ZAdd pkg name. err: %s", result.Err())
			}
		}

		if _, err = pipe.Exec(); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}

// InsertMicrosoft :
func (r *RedisDriver) InsertMicrosoft(cveXMLs []models.MicrosoftXML, xls []models.MicrosoftBulletinSearch) (err error) {
	cves, products := ConvertMicrosoft(cveXMLs, xls)
	bar := pb.StartNew(len(cves))

	var pipe redis.Pipeliner
	pipe = r.conn.Pipeline()
	for _, p := range products {
		if result := pipe.ZAdd(
			zindMicrosoftProductIDPrefix+p.ProductID,
			redis.Z{Score: 0, Member: p.ProductName},
		); result.Err() != nil {
			return fmt.Errorf("Failed to ZAdd kbID. err: %s", result.Err())
		}
	}
	if _, err = pipe.Exec(); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	for _, cve := range cves {
		var pipe redis.Pipeliner
		pipe = r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if result := pipe.HSet(hashKeyPrefix+cve.CveID, "Microsoft", string(j)); result.Err() != nil {
			return fmt.Errorf("Failed to HSet CVE. err: %s", result.Err())
		}

		for _, msKBID := range cve.KBIDs {
			if result := pipe.ZAdd(
				zindMicrosoftKBIDPrefix+msKBID.KBID,
				redis.Z{Score: 0, Member: cve.CveID},
			); result.Err() != nil {
				return fmt.Errorf("Failed to ZAdd kbID. err: %s", result.Err())
			}
		}

		if _, err = pipe.Exec(); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}
