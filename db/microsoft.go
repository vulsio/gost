package db

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
)

// GetMicrosoft :
func (r *RDBDriver) GetMicrosoft(cveID string) (*models.MicrosoftCVE, error) {
	c := models.MicrosoftCVE{}
	if err := r.conn.
		Preload("Products").
		Preload("Products.ScoreSet").
		Preload("Products.KBs").
		Where(&models.MicrosoftCVE{CveID: cveID}).
		Take(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log15.Error("Failed to get Microsoft", "err", err)
		return nil, err
	}
	return &c, nil
}

// GetMicrosoftMulti :
func (r *RDBDriver) GetMicrosoftMulti(cveIDs []string) (map[string]models.MicrosoftCVE, error) {
	cs := []models.MicrosoftCVE{}
	if err := r.conn.
		Preload("Products").
		Preload("Products.ScoreSet").
		Preload("Products.KBs").
		Where("cve_id IN ?", cveIDs).
		Find(&cs).Error; err != nil {
		log15.Error("Failed to get Microsoft", "err", err)
		return nil, err
	}

	m := map[string]models.MicrosoftCVE{}
	for _, c := range cs {
		m[c.CveID] = c
	}
	return m, nil
}

// GetExpandKB :
func (r *RDBDriver) GetExpandKB(applied []string, unapplied []string) ([]string, []string, error) {
	uniqAppliedKBIDs := map[string]struct{}{}
	uniqUnappliedKBIDs := map[string]struct{}{}
	for _, kbID := range applied {
		uniqAppliedKBIDs[kbID] = struct{}{}
	}
	for _, kbID := range unapplied {
		uniqUnappliedKBIDs[kbID] = struct{}{}
		delete(uniqAppliedKBIDs, kbID)
	}
	applied = maps.Keys(uniqAppliedKBIDs)

	if len(applied) > 0 {
		relations := []models.MicrosoftKBRelation{}

		if err := r.conn.
			Preload("SupersededBy").
			Where("kb_id IN ?", applied).
			Find(&relations).Error; err != nil {
			return nil, nil, xerrors.Errorf("Failed to get KB Relation by applied KBID: %q. err: %w", applied, err)
		}

		for _, relation := range relations {
			isInApplied := false
			for _, supersededby := range relation.SupersededBy {
				if slices.Contains(applied, supersededby.KBID) {
					isInApplied = true
					break
				}
			}
			if !isInApplied {
				for _, supersededby := range relation.SupersededBy {
					uniqUnappliedKBIDs[supersededby.KBID] = struct{}{}
				}
			}
		}
	}

	if len(uniqUnappliedKBIDs) > 0 {
		relations := []models.MicrosoftKBRelation{}

		if err := r.conn.
			Preload("SupersededBy").
			Where("kb_id IN ?", maps.Keys(uniqUnappliedKBIDs)).
			Find(&relations).Error; err != nil {
			return nil, nil, xerrors.Errorf("Failed to get KB Relation by unapplied KBID: %q. err: %w", unapplied, err)
		}

		for _, relation := range relations {
			for _, supersededby := range relation.SupersededBy {
				uniqUnappliedKBIDs[supersededby.KBID] = struct{}{}
			}
		}
	}

	return applied, maps.Keys(uniqUnappliedKBIDs), nil
}

// GetRelatedProducts :
func (r *RDBDriver) GetRelatedProducts(release string, kbs []string) ([]string, error) {
	if len(kbs) == 0 {
		return []string{}, nil
	}

	var products []string
	if err := r.conn.
		Model(&models.MicrosoftProduct{}).
		Distinct("microsoft_products.name").
		Joins("JOIN microsoft_kbs ON microsoft_kbs.microsoft_product_id = microsoft_products.id AND microsoft_kbs.article IN ?", kbs).
		Find(&products).Error; err != nil {
		return nil, xerrors.Errorf("Failed to detect Products. err: %w", err)
	}

	if release == "" {
		return products, nil
	}
	var filtered []string
	for _, p := range products {
		switch {
		case strings.Contains(p, "Microsoft Windows 2000"), // Microsoft Windows 2000; Microsoft Windows 2000 Server
			strings.Contains(p, "Microsoft Windows XP"),          // Microsoft Windows XP
			strings.Contains(p, "Microsoft Windows Server 2003"), // Microsoft Windows Server 2003; Microsoft Windows Server 2003 R2
			strings.Contains(p, "Windows Vista"),                 // Windows Vista
			strings.Contains(p, "Windows Server 2008"),           // Windows Server 2008; Windows Server 2008 R2
			strings.Contains(p, "Windows 7"),                     // Windows 7
			strings.Contains(p, "Windows 8"),                     // Windows 8
			strings.Contains(p, "Windows Server 2012"),           // Windows Server 2012; Windows Server 2012 R2
			strings.Contains(p, "Windows 8.1"),                   // Windows 8.1
			strings.Contains(p, "Windows RT 8.1"),                // Windows RT 8.1
			strings.Contains(p, "Windows 10"),                    // Windows 10
			strings.Contains(p, "Windows 11"),                    // Windows 11
			strings.Contains(p, "Windows Server 2016"),           // Windows Server 2016
			strings.Contains(p, "Windows Server 2019"),           // Windows Server 2019
			strings.Contains(p, "Windows Server, Version"),       // Windows Server, Version
			strings.Contains(p, "Windows Server 2022"):           // Windows Server 2022
			if strings.HasSuffix(p, release) {
				filtered = append(filtered, p)
			}
		default:
			filtered = append(filtered, p)
		}
	}
	return filtered, nil
}

// GetFilteredCvesMicrosoft :
func (r *RDBDriver) GetFilteredCvesMicrosoft(products []string, kbs []string) (map[string]models.MicrosoftCVE, error) {
	var q *gorm.DB
	if len(products) > 0 {
		q = r.conn.Preload("Products", "name IN ?", products)
	} else {
		q = r.conn.Preload("Products")
	}

	cves, cs := []models.MicrosoftCVE{}, []models.MicrosoftCVE{}
	if err := q.
		Preload("Products.ScoreSet").
		Preload("Products.KBs").
		FindInBatches(&cs, 998, func(_ *gorm.DB, _ int) error {
			cves = append(cves, cs...)
			return nil
		}).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get Microsoft. err: %w", err)
	}

	detected := map[string]models.MicrosoftCVE{}
	for _, c := range cves {
		ps := []models.MicrosoftProduct{}
		for _, p := range c.Products {
			if len(kbs) == 0 || len(p.KBs) == 0 {
				ps = append(ps, p)
				continue
			}

			filtered := []models.MicrosoftKB{}
			for _, kb := range p.KBs {
				if _, err := strconv.Atoi(kb.Article); err != nil {
					filtered = append(filtered, kb)
				} else if slices.Contains(kbs, kb.Article) {
					filtered = append(filtered, kb)
				}
			}
			if len(filtered) > 0 {
				p.KBs = filtered
				ps = append(ps, p)
			}
		}
		if len(ps) > 0 {
			c.Products = ps
			detected[c.CveID] = c
		}
	}
	return detected, nil
}

// InsertMicrosoft :
func (r *RDBDriver) InsertMicrosoft(cves []models.MicrosoftCVE, relations []models.MicrosoftKBRelation) error {
	log15.Info("Inserting cves", "cves", len(cves))
	if err := r.deleteAndInsertMicrosoft(cves); err != nil {
		return xerrors.Errorf("Failed to insert Microsoft CVE data. err: %w", err)
	}
	log15.Info("Insert KB Relation", "relations", len(relations))
	if err := r.deleteAndInsertMicrosoftKBRelation(relations); err != nil {
		return xerrors.Errorf("Failed to insert Microsoft KB Relation data. err: %w", err)
	}
	return nil
}

func (r *RDBDriver) deleteAndInsertMicrosoft(cves []models.MicrosoftCVE) (err error) {
	bar := pb.StartNew(len(cves)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{models.MicrosoftCVE{}, models.MicrosoftProduct{}, models.MicrosoftScoreSet{}, models.MicrosoftKB{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for idx := range chunkSlice(len(cves), batchSize) {
		if err = tx.Create(cves[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	return nil
}

func (r *RDBDriver) deleteAndInsertMicrosoftKBRelation(kbs []models.MicrosoftKBRelation) (err error) {
	bar := pb.StartNew(len(kbs)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{models.MicrosoftKBRelation{}, models.MicrosoftSupersededBy{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for idx := range chunkSlice(len(kbs), batchSize) {
		if err = tx.Create(kbs[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()
	return nil
}
