package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/config"
	"github.com/knqyf263/gost/models"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

/**
# Redis Data Structure

- Strings
  ┌───┬───────────────────┬──────────┬─────────────────────────────────────┐
  │NO │      KEY          │  VALUE   │             PURPOSE                 │
  └───┴───────────────────┴──────────┴─────────────────────────────────────┘
  ┌───┬───────────────────┬──────────┬─────────────────────────────────────┐
  │ 1 │ GOST#R#CVE#$CVEID │ $CVEJSON │ (RedHat) TO GET CVEJSON BY CVEID    │
  ├───┼───────────────────┼──────────┼─────────────────────────────────────┤
  │ 2 │ GOST#D#CVE#$CVEID │ $CVEJSON │ (Debian) TO GET CVEJSON BY CVEID    │
  ├───┼───────────────────┼──────────┼─────────────────────────────────────┤
  │ 3 │ GOST#U#CVE#$CVEID │ $CVEJSON │ (Ubuntu) TO GET CVEJSON BY CVEID    │
  ├───┼───────────────────┼──────────┼─────────────────────────────────────┤
  │ 4 │ GOST#M#CVE#$CVEID │ $CVEJSON │ (Microsoft) TO GET CVEJSON BY CVEID │
  └───┴───────────────────┴──────────┴─────────────────────────────────────┘

- Sets
  ┌───┬─────────────────────────┬──────────────┬─────────────────────────────────────────────┐
  │NO │    KEY                  │  MEMBER      │                PURPOSE                      │
  └───┴─────────────────────────┴──────────────┴─────────────────────────────────────────────┘
  ┌───┬─────────────────────────┬──────────────┬─────────────────────────────────────────────┐
  │ 1 │ GOST#R#PKG#$PKGNAME     │  $CVEID      │ (RedHat) GET RELATED []CVEID BY PKGNAME     │
  ├───┼─────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 2 │ GOST#D#PKG#$PKGNAME     │  $CVEID      │ (Debian) GET RELATED []CVEID BY PKGNAME     │
  ├───┼─────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 3 │ GOST#U#PKG#$PKGNAME     │  $CVEID      │ (Ubuntu) GET RELATED []CVEID BY PKGNAME     │
  ├───┼─────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 4 │ GOST#M#PKG#K#$KBID      │  $CVEID      │ (Microsoft) GET RELATED []CVEID BY KBID     │
  ├───┼─────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 5 │ GOST#M#PKG#P#$PRODUCTID │ $PRODUCTNAME │ (Microsoft) GET RELATED []PRODUCTNAME BY ID │
  └───┴─────────────────────────┴──────────────┴─────────────────────────────────────────────┘

- Hash
  ┌───┬────────────────┬───────────────┬────────┬──────────────────────────┐
  │NO │    KEY         │   FIELD       │  VALUE │       PURPOSE            │
  └───┴────────────────┴───────────────┴────────┴──────────────────────────┘
  ┌────────────────────┬───────────────┬────────┬──────────────────────────┐
  │ 1 │ GOST#FETCHMETA │   Revision    │ string │ GET Gost Binary Revision │
  ├───┼────────────────┼───────────────┼────────┼──────────────────────────┤
  │ 2 │ GOST#FETCHMETA │ SchemaVersion │  uint  │ GET Gost Schema Version  │
  └───┴────────────────┴───────────────┴────────┴──────────────────────────┘

**/

const (
	dialectRedis       = "redis"
	redHatKeyPrefix    = "GOST#R#"
	debianKeyPrefix    = "GOST#D#"
	ubuntuKeyPrefix    = "GOST#U#"
	microsoftKeyPrefix = "GOST#M#"
	fetchMetaKey       = "GOST#FETCHMETA"
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
	ctx := context.Background()
	var err error
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log15.Error("Failed to parse url.", "err", err)
		return err
	}
	r.conn = redis.NewClient(option)
	err = r.conn.Ping(ctx).Err()
	return err
}

// CloseDB close Database
func (r *RedisDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// IsGostModelV1 determines if the DB was created at the time of Gost Model v1
func (r *RedisDriver) IsGostModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		key, err := r.conn.RandomKey(ctx).Result()
		if err != nil {
			if err == redis.Nil {
				return false, nil
			}
			return false, fmt.Errorf("Failed to RandomKey. err: %s", err)
		}
		if key != "" {
			return true, nil
		}
	}

	return false, nil
}

// GetFetchMeta get FetchMeta from Database
func (r *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GostRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet Revision. err: %s", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet SchemaVersion. err: %s", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("Failed to ParseUint. err: %s", err)
	}

	return &models.FetchMeta{GostRevision: revision, SchemaVersion: uint(version)}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GostRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}

// GetAfterTimeRedhat :
func (r *RedisDriver) GetAfterTimeRedhat(after time.Time) ([]models.RedhatCVE, error) {
	allCves := []models.RedhatCVE{}

	ctx := context.Background()
	keys, err := r.conn.Keys(ctx, fmt.Sprintf("%sCVE#*", redHatKeyPrefix)).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to Keys. err: %s", err)
	}

	cves := r.GetRedhatMulti(keys)
	for _, cve := range cves {
		if !after.After(cve.PublicDate) {
			allCves = append(allCves, cve)
		}
	}

	return allCves, nil
}

// GetRedhat :
func (r *RedisDriver) GetRedhat(cveID string) *models.RedhatCVE {
	ctx := context.Background()
	cve, err := r.conn.Get(ctx, fmt.Sprintf("%sCVE#%s", redHatKeyPrefix, cveID)).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}

	var redhat models.RedhatCVE
	if err := json.Unmarshal([]byte(cve), &redhat); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return nil
	}
	return &redhat
}

// GetRedhatMulti :
func (r *RedisDriver) GetRedhatMulti(cveIDs []string) map[string]models.RedhatCVE {
	results := map[string]models.RedhatCVE{}

	keys := make([]string, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		keys = append(keys, fmt.Sprintf("%sCVE#%s", redHatKeyPrefix, cveID))
	}

	ctx := context.Background()
	cves, err := r.conn.MGet(ctx, keys...).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}
	for _, cve := range cves {
		var redhat models.RedhatCVE
		if err := json.Unmarshal([]byte(cve.(string)), &redhat); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
		results[redhat.Name] = redhat
	}

	return results
}

// GetUnfixedCvesRedhat :
func (r *RedisDriver) GetUnfixedCvesRedhat(major, pkgName string, ignoreWillNotFix bool) map[string]models.RedhatCVE {
	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf("%sPKG#%s", redHatKeyPrefix, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to get pkg.", "err", err)
		return nil
	}

	m := map[string]models.RedhatCVE{}
	cpe := fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", major)
	for _, cveID := range cveIDs {
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
	return m
}

// GetUnfixedCvesDebian : get the CVEs related to debian_release.status = 'open', major, pkgName
func (r *RedisDriver) GetUnfixedCvesDebian(major, pkgName string) map[string]models.DebianCVE {
	return r.getCvesDebianWithFixStatus(major, pkgName, "open")
}

// GetFixedCvesDebian : get the CVEs related to debian_release.status = 'resolved', major, pkgName
func (r *RedisDriver) GetFixedCvesDebian(major, pkgName string) map[string]models.DebianCVE {
	return r.getCvesDebianWithFixStatus(major, pkgName, "resolved")
}

func (r *RedisDriver) getCvesDebianWithFixStatus(major, pkgName, fixStatus string) map[string]models.DebianCVE {
	codeName, ok := debVerCodename[major]
	if !ok {
		log15.Error("Not supported yet", "major", major)
		return nil
	}

	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf("%sPKG#%s", debianKeyPrefix, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to get pkg.", "err", err)
		return nil
	}

	m := map[string]models.DebianCVE{}
	for _, cveID := range cveIDs {
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
				if rel.ProductName == codeName && rel.Status == fixStatus {
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
	return m
}

// GetDebian :
func (r *RedisDriver) GetDebian(cveID string) *models.DebianCVE {
	ctx := context.Background()
	cve, err := r.conn.Get(ctx, fmt.Sprintf("%sCVE#%s", debianKeyPrefix, cveID)).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}

	var deb models.DebianCVE
	if err := json.Unmarshal([]byte(cve), &deb); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return nil
	}
	return &deb
}

// GetUnfixedCvesUbuntu :
func (r *RedisDriver) GetUnfixedCvesUbuntu(major, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"needed", "pending"})
}

// GetFixedCvesUbuntu :
func (r *RedisDriver) GetFixedCvesUbuntu(major, pkgName string) map[string]models.UbuntuCVE {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"released"})
}

func (r *RedisDriver) getCvesUbuntuWithFixStatus(major, pkgName string, fixStatus []string) map[string]models.UbuntuCVE {
	codeName, ok := ubuntuVerCodename[major]
	if !ok {
		log15.Error("Not supported yet", "major", major)
		return nil
	}

	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf("%sPKG#%s", ubuntuKeyPrefix, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to get pkg.", "err", err)
		return nil
	}

	m := map[string]models.UbuntuCVE{}
	for _, cveID := range cveIDs {
		cve := r.GetUbuntu(cveID)
		if cve == nil {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			continue
		}

		patches := []models.UbuntuPatch{}
		for _, p := range cve.Patches {
			if p.PackageName != pkgName {
				continue
			}
			relPatches := []models.UbuntuReleasePatch{}
			for _, relPatch := range p.ReleasePatches {
				if relPatch.ReleaseName == codeName {
					for _, s := range fixStatus {
						if s == relPatch.Status {
							relPatches = append(relPatches, relPatch)
						}
					}
				}
			}
			if len(relPatches) == 0 {
				continue
			}
			p.ReleasePatches = relPatches
			patches = append(patches, p)
		}
		if len(patches) != 0 {
			cve.Patches = patches
			m[cveID] = *cve
		}
	}
	return m
}

// GetUbuntu :
func (r *RedisDriver) GetUbuntu(cveID string) *models.UbuntuCVE {
	ctx := context.Background()
	cve, err := r.conn.Get(ctx, fmt.Sprintf("%sCVE#%s", ubuntuKeyPrefix, cveID)).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}

	var c models.UbuntuCVE
	if err := json.Unmarshal([]byte(cve), &c); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return nil
	}
	return &c
}

// GetMicrosoft :
func (r *RedisDriver) GetMicrosoft(cveID string) *models.MicrosoftCVE {
	ctx := context.Background()
	cve, err := r.conn.Get(ctx, fmt.Sprintf("%sCVE#%s", microsoftKeyPrefix, cveID)).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}

	var ms models.MicrosoftCVE
	if err := json.Unmarshal([]byte(cve), &ms); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return nil
	}
	return &ms
}

// GetMicrosoftMulti :
func (r *RedisDriver) GetMicrosoftMulti(cveIDs []string) map[string]models.MicrosoftCVE {
	results := map[string]models.MicrosoftCVE{}

	keys := make([]string, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		keys = append(keys, fmt.Sprintf("%sCVE#%s", microsoftKeyPrefix, cveID))
	}

	ctx := context.Background()
	cves, err := r.conn.MGet(ctx, keys...).Result()
	if err != nil {
		log15.Error("Failed to get cve.", "err", err)
		return nil
	}

	for _, cve := range cves {
		var ms models.MicrosoftCVE
		if err := json.Unmarshal([]byte(cve.(string)), &ms); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
		results[ms.CveID] = ms
	}

	return results
}

//InsertRedhat :
func (r *RedisDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	expire := viper.GetUint("expire")

	ctx := context.Background()
	cves, err := ConvertRedhat(cveJSONs)
	if err != nil {
		return err
	}
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		pipe := r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if err := pipe.Set(ctx, fmt.Sprintf("%sCVE#%s", redHatKeyPrefix, cve.Name), string(j), time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to Set CVE. err: %s", err)
		}
		for _, pkg := range cve.PackageState {
			key := fmt.Sprintf("%sPKG#%s", redHatKeyPrefix, pkg.PackageName)
			if err := pipe.SAdd(ctx, key, cve.Name).Err(); err != nil {
				return fmt.Errorf("Failed to SAdd pkg name. err: %s", err)
			}
			if expire > 0 {
				if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
					return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
				}
			} else {
				if err := pipe.Persist(ctx, key).Err(); err != nil {
					return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
				}
			}
		}

		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}

// InsertDebian :
func (r *RedisDriver) InsertDebian(cveJSONs models.DebianJSON) error {
	expire := viper.GetUint("expire")

	ctx := context.Background()
	cves := ConvertDebian(cveJSONs)
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		pipe := r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if result := pipe.Set(ctx, fmt.Sprintf("%sCVE#%s", debianKeyPrefix, cve.CveID), string(j), time.Duration(expire*uint(time.Second))); result.Err() != nil {
			return fmt.Errorf("Failed to Set CVE. err: %s", result.Err())
		}
		for _, pkg := range cve.Package {
			key := fmt.Sprintf("%sPKG#%s", debianKeyPrefix, pkg.PackageName)
			if err := pipe.SAdd(ctx, key, cve.CveID).Err(); err != nil {
				return fmt.Errorf("Failed to SAdd pkg name. err: %s", err)
			}
			if expire > 0 {
				if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
					return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
				}
			} else {
				if err := pipe.Persist(ctx, key).Err(); err != nil {
					return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
				}
			}
		}

		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}

// InsertUbuntu :
func (r *RedisDriver) InsertUbuntu(cveJSONs []models.UbuntuCVEJSON) (err error) {
	expire := viper.GetUint("expire")

	ctx := context.Background()
	cves := ConvertUbuntu(cveJSONs)
	bar := pb.StartNew(len(cves))

	for _, cve := range cves {
		pipe := r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if err := pipe.Set(ctx, fmt.Sprintf("%sCVE#%s", ubuntuKeyPrefix, cve.Candidate), string(j), time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to Set CVE. err: %s", err)
		}
		for _, pkg := range cve.Patches {
			key := fmt.Sprintf("%sPKG#%s", ubuntuKeyPrefix, pkg.PackageName)
			if err := pipe.SAdd(ctx, key, cve.Candidate).Err(); err != nil {
				return fmt.Errorf("Failed to SAdd pkg name. err: %s", err)
			}
			if expire > 0 {
				if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
					return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
				}
			} else {
				if err := pipe.Persist(ctx, key).Err(); err != nil {
					return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
				}
			}
		}

		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}

// InsertMicrosoft :
func (r *RedisDriver) InsertMicrosoft(cveXMLs []models.MicrosoftXML, xls []models.MicrosoftBulletinSearch) (err error) {
	expire := viper.GetUint("expire")

	ctx := context.Background()
	cves, products := ConvertMicrosoft(cveXMLs, xls)
	bar := pb.StartNew(len(cves))

	pipe := r.conn.Pipeline()
	for _, p := range products {
		key := fmt.Sprintf("%sPKG#P#%s", microsoftKeyPrefix, p.ProductID)
		if err := pipe.SAdd(ctx, key, p.ProductName).Err(); err != nil {
			return fmt.Errorf("Failed to SAdd ProductID. err: %s", err)
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, key).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	for _, cve := range cves {
		pipe := r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(cve)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		cveID := strings.ReplaceAll(strings.ReplaceAll(cve.CveID, "\n", ""), " ", "")
		key := fmt.Sprintf("%sCVE#%s", microsoftKeyPrefix, cveID)
		if err := pipe.Set(ctx, key, string(j), time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to HSet CVE. err: %s", err)
		}
		for _, msKBID := range cve.KBIDs {
			key := fmt.Sprintf("%sPKG#K#%s", microsoftKeyPrefix, msKBID.KBID)
			if err := pipe.SAdd(ctx, key, cve.CveID).Err(); err != nil {
				return fmt.Errorf("Failed to SAdd kbID. err: %s", err)
			}
			if expire > 0 {
				if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
					return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
				}
			} else {
				if err := pipe.Persist(ctx, key).Err(); err != nil {
					return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
				}
			}
		}

		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	bar.Finish()
	return nil
}
