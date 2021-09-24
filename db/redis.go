package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/config"
	"github.com/vulsio/gost/models"
	"golang.org/x/xerrors"
)

/**
# Redis Data Structure

- Sets
  ┌───┬──────────────────────────┬──────────────┬─────────────────────────────────────────────┐
  │NO │    KEY                   │  MEMBER      │                PURPOSE                      │
  └───┴──────────────────────────┴──────────────┴─────────────────────────────────────────────┘
  ┌───┬──────────────────────────┬──────────────┬─────────────────────────────────────────────┐
  │ 1 │ GOST#RH#PKG#$PKGNAME     │  $CVEID      │ (RedHat) GET RELATED []CVEID BY PKGNAME     │
  ├───┼──────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 2 │ GOST#DEB#PKG#$PKGNAME    │  $CVEID      │ (Debian) GET RELATED []CVEID BY PKGNAME     │
  ├───┼──────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 3 │ GOST#UBU#PKG#$PKGNAME    │  $CVEID      │ (Ubuntu) GET RELATED []CVEID BY PKGNAME     │
  ├───┼──────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 4 │ GOST#MS#PKG#K#$KBID      │  $CVEID      │ (Microsoft) GET RELATED []CVEID BY KBID     │
  ├───┼──────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ 5 │ GOST#MS#PKG#P#$PRODUCTID │ $PRODUCTNAME │ (Microsoft) GET RELATED []PRODUCTNAME BY ID │
  └───┴──────────────────────────┴──────────────┴─────────────────────────────────────────────┘

- Hash
  ┌───┬────────────────┬───────────────┬──────────┬────────────────────────────────────────────────┐
  │NO │    KEY         │     FIELD     │   VALUE  │                  PURPOSE                       │
  └───┴────────────────┴───────────────┴──────────┴────────────────────────────────────────────────┘
  ┌───┬────────────────┬───────────────┬──────────┬────────────────────────────────────────────────┐
  │ 1 │ GOST#RH#CVE    │    $CVEID     │ $CVEJSON │ (RedHat) TO GET CVEJSON BY CVEID               │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 2 │ GOST#DEB#CVE   │    $CVEID     │ $CVEJSON │ (RedHat) TO GET CVEJSON BY CVEID               │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 3 │ GOST#UBU#CVE   │    $CVEID     │ $CVEJSON │ (RedHat) TO GET CVEJSON BY CVEID               │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 4 │ GOST#MS#CVE    │    $CVEID     │ $CVEJSON │ (RedHat) TO GET CVEJSON BY CVEID               │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 5 │ GOST#DEP       │ RH/DEB/UBU/MS │   JSON   │ TO DELETE OUTDATED AND UNNEEDED KEY AND MEMBER │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 6 │ GOST#FETCHMETA │   Revision    │  string  │ GET Gost Binary Revision                       │
  ├───┼────────────────┼───────────────┼──────────┼────────────────────────────────────────────────┤
  │ 7 │ GOST#FETCHMETA │ SchemaVersion │   uint   │ GET Gost Schema Version                        │
  └───┴────────────────┴───────────────┴──────────┴────────────────────────────────────────────────┘

**/

const (
	dialectRedis  = "redis"
	cveKeyFormat  = "GOST#%s#CVE"
	pkgKeyFormat  = "GOST#%s#PKG#%s"
	redhatName    = "RH"
	debianName    = "DEB"
	ubuntuName    = "UBU"
	microsoftName = "MS"
	depKey        = "GOST#DEP"
	fetchMetaKey  = "GOST#FETCHMETA"
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
		keys, _, err := r.conn.Scan(ctx, 0, "GOST#*", 1).Result()
		if err != nil {
			return false, fmt.Errorf("Failed to Scan. err: %s", err)
		}
		if len(keys) == 0 {
			return false, nil
		}
		return true, nil
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
	ctx := context.Background()

	cves, err := r.conn.HGetAll(ctx, fmt.Sprintf(cveKeyFormat, redhatName)).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGetAll. err: %s", err)
	}
	if len(cves) == 0 {
		return []models.RedhatCVE{}, nil
	}

	allCves := []models.RedhatCVE{}
	for _, cvestr := range cves {
		var cve models.RedhatCVE
		if err := json.Unmarshal([]byte(cvestr), &cve); err != nil {
			return nil, fmt.Errorf("Failed to Unmarshal json. err: %s", err)
		}

		if !after.After(cve.PublicDate) {
			allCves = append(allCves, cve)
		}
	}

	return allCves, nil
}

// GetRedhat :
func (r *RedisDriver) GetRedhat(cveID string) (models.RedhatCVE, error) {
	cve, err := r.conn.HGet(context.Background(), fmt.Sprintf(cveKeyFormat, redhatName), cveID).Result()
	if err != nil {
		log15.Error("Failed to HGet.", "err", err)
		return models.RedhatCVE{}, err
	}

	var redhat models.RedhatCVE
	if err := json.Unmarshal([]byte(cve), &redhat); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return models.RedhatCVE{}, err
	}
	return redhat, nil
}

// GetRedhatMulti :
func (r *RedisDriver) GetRedhatMulti(cveIDs []string) (map[string]models.RedhatCVE, error) {
	if len(cveIDs) == 0 {
		return map[string]models.RedhatCVE{}, nil
	}

	cves, err := r.conn.HMGet(context.Background(), fmt.Sprintf(cveKeyFormat, redhatName), cveIDs...).Result()
	if err != nil {
		log15.Error("Failed to HMGet.", "err", err)
		return nil, err
	}

	results := map[string]models.RedhatCVE{}
	for _, cve := range cves {
		if cve == nil {
			continue
		}

		var redhat models.RedhatCVE
		if err := json.Unmarshal([]byte(cve.(string)), &redhat); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil, err
		}
		results[redhat.Name] = redhat
	}
	return results, nil
}

// GetUnfixedCvesRedhat :
func (r *RedisDriver) GetUnfixedCvesRedhat(major, pkgName string, ignoreWillNotFix bool) (map[string]models.RedhatCVE, error) {
	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(pkgKeyFormat, redhatName, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to SMembers.", "err", err)
		return nil, err
	}

	m := map[string]models.RedhatCVE{}
	cpe := fmt.Sprintf("cpe:/o:redhat:enterprise_linux:%s", major)
	for _, cveID := range cveIDs {
		red, err := r.GetRedhat(cveID)
		if err != nil {
			return nil, err
		}
		if red.Name == "" {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			return nil, xerrors.New("Failed to get CVE registered in relation to the package.")
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
		m[cveID] = red
	}
	return m, nil
}

// GetUnfixedCvesDebian : get the CVEs related to debian_release.status = 'open', major, pkgName
func (r *RedisDriver) GetUnfixedCvesDebian(major, pkgName string) (map[string]models.DebianCVE, error) {
	return r.getCvesDebianWithFixStatus(major, pkgName, "open")
}

// GetFixedCvesDebian : get the CVEs related to debian_release.status = 'resolved', major, pkgName
func (r *RedisDriver) GetFixedCvesDebian(major, pkgName string) (map[string]models.DebianCVE, error) {
	return r.getCvesDebianWithFixStatus(major, pkgName, "resolved")
}

func (r *RedisDriver) getCvesDebianWithFixStatus(major, pkgName, fixStatus string) (map[string]models.DebianCVE, error) {
	codeName, ok := debVerCodename[major]
	if !ok {
		log15.Error("Not supported yet", "major", major)
		return nil, xerrors.Errorf("Failed to convert from major version to codename. err: Debian %s is not supported yet", major)
	}

	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(pkgKeyFormat, debianName, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to SMembers.", "err", err)
		return nil, err
	}

	m := map[string]models.DebianCVE{}
	for _, cveID := range cveIDs {
		deb, err := r.GetDebian(cveID)
		if err != nil {
			return nil, err
		}
		if deb.CveID == "" {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			return nil, xerrors.New("Failed to get CVE registered in relation to the package.")
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
			m[cveID] = deb
		}
	}
	return m, nil
}

// GetDebian :
func (r *RedisDriver) GetDebian(cveID string) (models.DebianCVE, error) {
	cve, err := r.conn.HGet(context.Background(), fmt.Sprintf(cveKeyFormat, debianName), cveID).Result()
	if err != nil {
		log15.Error("Failed to HGet.", "err", err)
		return models.DebianCVE{}, err
	}

	var deb models.DebianCVE
	if err := json.Unmarshal([]byte(cve), &deb); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return models.DebianCVE{}, err
	}
	return deb, nil
}

// GetDebianMulti :
func (r *RedisDriver) GetDebianMulti(cveIDs []string) (map[string]models.DebianCVE, error) {
	if len(cveIDs) == 0 {
		return map[string]models.DebianCVE{}, nil
	}

	cves, err := r.conn.HMGet(context.Background(), fmt.Sprintf(cveKeyFormat, debianName), cveIDs...).Result()
	if err != nil {
		log15.Error("Failed to HMGet.", "err", err)
		return nil, err
	}

	results := map[string]models.DebianCVE{}
	for _, cve := range cves {
		if cve == nil {
			continue
		}

		var debian models.DebianCVE
		if err := json.Unmarshal([]byte(cve.(string)), &debian); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil, err
		}
		results[debian.CveID] = debian
	}
	return results, nil
}

// GetUnfixedCvesUbuntu :
func (r *RedisDriver) GetUnfixedCvesUbuntu(major, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"needed", "pending"})
}

// GetFixedCvesUbuntu :
func (r *RedisDriver) GetFixedCvesUbuntu(major, pkgName string) (map[string]models.UbuntuCVE, error) {
	return r.getCvesUbuntuWithFixStatus(major, pkgName, []string{"released"})
}

func (r *RedisDriver) getCvesUbuntuWithFixStatus(major, pkgName string, fixStatus []string) (map[string]models.UbuntuCVE, error) {
	codeName, ok := ubuntuVerCodename[major]
	if !ok {
		log15.Error("Not supported yet", "major", major)
		return nil, xerrors.Errorf("Failed to convert from major version to codename. err: Ubuntu %s is not supported yet", major)
	}

	ctx := context.Background()
	cveIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(pkgKeyFormat, ubuntuName, pkgName)).Result()
	if err != nil {
		log15.Error("Failed to SMembers.", "err", err)
		return nil, err
	}

	m := map[string]models.UbuntuCVE{}
	for _, cveID := range cveIDs {
		cve, err := r.GetUbuntu(cveID)
		if err != nil {
			return nil, err
		}
		if cve.Candidate == "" {
			log15.Error("CVE is not found", "CVE-ID", cveID)
			return nil, xerrors.New("Failed to get CVE registered in relation to the package.")
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
			m[cveID] = cve
		}
	}
	return m, nil
}

// GetUbuntu :
func (r *RedisDriver) GetUbuntu(cveID string) (models.UbuntuCVE, error) {
	cve, err := r.conn.HGet(context.Background(), fmt.Sprintf(cveKeyFormat, ubuntuName), cveID).Result()
	if err != nil {
		log15.Error("Failed to HGet.", "err", err)
		return models.UbuntuCVE{}, err
	}

	var c models.UbuntuCVE
	if err := json.Unmarshal([]byte(cve), &c); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return models.UbuntuCVE{}, err
	}
	return c, nil
}

// GetUbuntuMulti :
func (r *RedisDriver) GetUbuntuMulti(cveIDs []string) (map[string]models.UbuntuCVE, error) {
	if len(cveIDs) == 0 {
		return map[string]models.UbuntuCVE{}, nil
	}

	cves, err := r.conn.HMGet(context.Background(), fmt.Sprintf(cveKeyFormat, ubuntuName), cveIDs...).Result()
	if err != nil {
		log15.Error("Failed to HMGet.", "err", err)
		return nil, err
	}

	results := map[string]models.UbuntuCVE{}
	for _, cve := range cves {
		if cve == nil {
			continue
		}

		var ubuntu models.UbuntuCVE
		if err := json.Unmarshal([]byte(cve.(string)), &ubuntu); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil, err
		}
		results[ubuntu.Candidate] = ubuntu
	}
	return results, nil
}

// GetMicrosoft :
func (r *RedisDriver) GetMicrosoft(cveID string) (models.MicrosoftCVE, error) {
	cve, err := r.conn.HGet(context.Background(), fmt.Sprintf(cveKeyFormat, microsoftName), cveID).Result()
	if err != nil {
		log15.Error("Failed to HGet.", "err", err)
		return models.MicrosoftCVE{}, err
	}

	var ms models.MicrosoftCVE
	if err := json.Unmarshal([]byte(cve), &ms); err != nil {
		log15.Error("Failed to Unmarshal json.", "err", err)
		return models.MicrosoftCVE{}, err
	}
	return ms, nil
}

// GetMicrosoftMulti :
func (r *RedisDriver) GetMicrosoftMulti(cveIDs []string) (map[string]models.MicrosoftCVE, error) {
	if len(cveIDs) == 0 {
		return map[string]models.MicrosoftCVE{}, nil
	}

	cves, err := r.conn.HMGet(context.Background(), fmt.Sprintf(cveKeyFormat, microsoftName), cveIDs...).Result()
	if err != nil {
		log15.Error("Failed to HMGet.", "err", err)
		return nil, err
	}

	results := map[string]models.MicrosoftCVE{}
	for _, cve := range cves {
		if cve == nil {
			continue
		}

		var ms models.MicrosoftCVE
		if err := json.Unmarshal([]byte(cve.(string)), &ms); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil, err
		}
		results[ms.CveID] = ms
	}

	return results, nil
}

//InsertRedhat :
func (r *RedisDriver) InsertRedhat(cveJSONs []models.RedhatCVEJSON) (err error) {
	cves, err := ConvertRedhat(cveJSONs)
	if err != nil {
		return err
	}

	ctx := context.Background()
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"PKGNAME": {}}}
	newDeps := map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.HGet(ctx, depKey, redhatName).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	bar := pb.StartNew(len(cves))
	for idx := range chunkSlice(len(cves), batchSize) {
		pipe := r.conn.Pipeline()
		cvekey := fmt.Sprintf(cveKeyFormat, redhatName)
		for _, cve := range cves[idx.From:idx.To] {
			j, err := json.Marshal(cve)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			if err := pipe.HSet(ctx, cvekey, cve.Name, string(j)).Err(); err != nil {
				return fmt.Errorf("Failed to HSet CVE. err: %s", err)
			}
			if _, ok := newDeps[cve.Name]; !ok {
				newDeps[cve.Name] = map[string]struct{}{}
			}

			for _, pkg := range cve.PackageState {
				key := fmt.Sprintf(pkgKeyFormat, redhatName, pkg.PackageName)
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

				newDeps[cve.Name][pkg.PackageName] = struct{}{}
				if _, ok := oldDeps[cve.Name]; ok {
					delete(oldDeps[cve.Name], pkg.PackageName)
				}
			}
			if _, ok := oldDeps[cve.Name]; ok {
				if len(oldDeps[cve.Name]) == 0 {
					delete(oldDeps, cve.Name)
				}
			}
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, cvekey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, cvekey).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, pkgs := range oldDeps {
		for pkgName := range pkgs {
			if err := pipe.SRem(ctx, fmt.Sprintf(pkgKeyFormat, redhatName, pkgName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if _, ok := newDeps[cveID]; !ok {
			if err := pipe.HDel(ctx, fmt.Sprintf(cveKeyFormat, redhatName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to HDel. err: %s", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.HSet(ctx, depKey, redhatName, string(newDepsJSON)).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if expire > 0 {
		if err := pipe.Expire(ctx, depKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
		}
	} else {
		if err := pipe.Persist(ctx, depKey).Err(); err != nil {
			return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
		}
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	return nil
}

// InsertDebian :
func (r *RedisDriver) InsertDebian(cveJSONs models.DebianJSON) error {
	cves := ConvertDebian(cveJSONs)

	ctx := context.Background()
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"PKGNAME": {}}}
	newDeps := map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.HGet(ctx, depKey, debianName).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	bar := pb.StartNew(len(cves))
	for idx := range chunkSlice(len(cves), batchSize) {
		pipe := r.conn.Pipeline()
		cvekey := fmt.Sprintf(cveKeyFormat, debianName)
		for _, cve := range cves[idx.From:idx.To] {
			j, err := json.Marshal(cve)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			if result := pipe.HSet(ctx, cvekey, cve.CveID, string(j)); result.Err() != nil {
				return fmt.Errorf("Failed to HSet CVE. err: %s", result.Err())
			}
			if _, ok := newDeps[cve.CveID]; !ok {
				newDeps[cve.CveID] = map[string]struct{}{}
			}

			for _, pkg := range cve.Package {
				key := fmt.Sprintf(pkgKeyFormat, debianName, pkg.PackageName)
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

				newDeps[cve.CveID][pkg.PackageName] = struct{}{}
				if _, ok := oldDeps[cve.CveID]; ok {
					delete(oldDeps[cve.CveID], pkg.PackageName)
				}
			}
			if _, ok := oldDeps[cve.CveID]; ok {
				if len(oldDeps[cve.CveID]) == 0 {
					delete(oldDeps, cve.CveID)
				}
			}
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, cvekey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, cvekey).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, pkgs := range oldDeps {
		for pkgName := range pkgs {
			if err := pipe.SRem(ctx, fmt.Sprintf(pkgKeyFormat, debianName, pkgName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if _, ok := newDeps[cveID]; !ok {
			if err := pipe.HDel(ctx, fmt.Sprintf(cveKeyFormat, debianName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to HDel. err: %s", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.HSet(ctx, depKey, debianName, string(newDepsJSON)).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if expire > 0 {
		if err := pipe.Expire(ctx, depKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
		}
	} else {
		if err := pipe.Persist(ctx, depKey).Err(); err != nil {
			return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
		}
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	return nil
}

// InsertUbuntu :
func (r *RedisDriver) InsertUbuntu(cveJSONs []models.UbuntuCVEJSON) (err error) {
	cves := ConvertUbuntu(cveJSONs)

	ctx := context.Background()
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"PKGNAME": {}}}
	newDeps := map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.HGet(ctx, depKey, ubuntuName).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	bar := pb.StartNew(len(cves))
	for idx := range chunkSlice(len(cves), batchSize) {
		pipe := r.conn.Pipeline()
		cvekey := fmt.Sprintf(cveKeyFormat, ubuntuName)
		for _, cve := range cves[idx.From:idx.To] {
			j, err := json.Marshal(cve)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			if err := pipe.HSet(ctx, cvekey, cve.Candidate, string(j)).Err(); err != nil {
				return fmt.Errorf("Failed to HSet CVE. err: %s", err)
			}
			if _, ok := newDeps[cve.Candidate]; !ok {
				newDeps[cve.Candidate] = map[string]struct{}{}
			}

			for _, pkg := range cve.Patches {
				key := fmt.Sprintf(pkgKeyFormat, ubuntuName, pkg.PackageName)
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

				newDeps[cve.Candidate][pkg.PackageName] = struct{}{}
				if _, ok := oldDeps[cve.Candidate]; ok {
					delete(oldDeps[cve.Candidate], pkg.PackageName)
				}
			}
			if _, ok := oldDeps[cve.Candidate]; ok {
				if len(oldDeps[cve.Candidate]) == 0 {
					delete(oldDeps, cve.Candidate)
				}
			}
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, cvekey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, cvekey).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, pkgs := range oldDeps {
		for pkgName := range pkgs {
			if err := pipe.SRem(ctx, fmt.Sprintf(pkgKeyFormat, ubuntuName, pkgName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if _, ok := newDeps[cveID]; !ok {
			if err := pipe.HDel(ctx, fmt.Sprintf(cveKeyFormat, ubuntuName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to HDel. err: %s", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.HSet(ctx, depKey, ubuntuName, string(newDepsJSON)).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if expire > 0 {
		if err := pipe.Expire(ctx, depKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
		}
	} else {
		if err := pipe.Persist(ctx, depKey).Err(); err != nil {
			return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
		}
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	return nil
}

// InsertMicrosoft :
func (r *RedisDriver) InsertMicrosoft(cveXMLs []models.MicrosoftXML, xls []models.MicrosoftBulletinSearch) (err error) {
	cves, products := ConvertMicrosoft(cveXMLs, xls)

	ctx := context.Background()
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"products": {"ProductID": {"ProductName": {}}}, "cves": {"CVEID": {"KBID": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{
		"products": {},
		"cves":     {},
	}
	oldDepsStr, err := r.conn.HGet(ctx, depKey, microsoftName).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = `{
			"products":{},
			"cves": {}
		}`
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	log15.Info("Inserting products", "products", len(products))
	bar := pb.StartNew(len(products))
	for idx := range chunkSlice(len(products), batchSize) {
		pipe := r.conn.Pipeline()
		for _, p := range products[idx.From:idx.To] {
			key := fmt.Sprintf(pkgKeyFormat, microsoftName, fmt.Sprintf("P#%s", p.ProductID))
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

			if _, ok := newDeps["products"][p.ProductID]; !ok {
				newDeps["products"][p.ProductID] = map[string]struct{}{}
			}
			newDeps["products"][p.ProductID][p.ProductName] = struct{}{}
			if _, ok := oldDeps["products"][p.ProductID]; ok {
				delete(oldDeps["products"][p.ProductID], p.ProductName)
				if len(oldDeps["products"][p.ProductID]) == 0 {
					delete(oldDeps["products"], p.ProductID)
				}
			}
		}
		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting cves", "cves", len(cves))
	bar = pb.StartNew(len(cves))
	for idx := range chunkSlice(len(cves), batchSize) {
		pipe := r.conn.Pipeline()
		cvekey := fmt.Sprintf(cveKeyFormat, microsoftName)
		for _, cve := range cves[idx.From:idx.To] {
			j, err := json.Marshal(cve)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			if err := pipe.HSet(ctx, cvekey, cve.CveID, string(j)).Err(); err != nil {
				return fmt.Errorf("Failed to HSet CVE. err: %s", err)
			}
			if _, ok := newDeps["cves"][cve.CveID]; !ok {
				newDeps["cves"][cve.CveID] = map[string]struct{}{}
			}

			for _, msKBID := range cve.KBIDs {
				key := fmt.Sprintf(pkgKeyFormat, microsoftName, fmt.Sprintf("K#%s", msKBID.KBID))
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

				newDeps["cves"][cve.CveID][msKBID.KBID] = struct{}{}
				if _, ok := oldDeps["cves"][cve.CveID]; ok {
					delete(oldDeps["cves"][cve.CveID], msKBID.KBID)
				}
			}
			if _, ok := oldDeps["cves"][cve.CveID]; ok {
				if len(oldDeps["cves"][cve.CveID]) == 0 {
					delete(oldDeps["cves"], cve.CveID)
				}
			}
		}
		if expire > 0 {
			if err := pipe.Expire(ctx, cvekey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
				return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
			}
		} else {
			if err := pipe.Persist(ctx, cvekey).Err(); err != nil {
				return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
			}
		}
		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for productID, productNames := range oldDeps["products"] {
		for productName := range productNames {
			if err := pipe.SRem(ctx, fmt.Sprintf(pkgKeyFormat, microsoftName, fmt.Sprintf("P#%s", productID)), productName).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
	}
	for cveID, kbIDs := range oldDeps["cves"] {
		for kbID := range kbIDs {
			if err := pipe.SRem(ctx, fmt.Sprintf(pkgKeyFormat, microsoftName, fmt.Sprintf("K#%s", kbID)), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to SRem. err: %s", err)
			}
		}
		if _, ok := newDeps[cveID]; !ok {
			if err := pipe.HDel(ctx, fmt.Sprintf(cveKeyFormat, microsoftName), cveID).Err(); err != nil {
				return fmt.Errorf("Failed to HDel. err: %s", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.HSet(ctx, depKey, microsoftName, string(newDepsJSON)).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if expire > 0 {
		if err := pipe.Expire(ctx, depKey, time.Duration(expire*uint(time.Second))).Err(); err != nil {
			return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
		}
	} else {
		if err := pipe.Persist(ctx, depKey).Err(); err != nil {
			return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
		}
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	return nil
}
