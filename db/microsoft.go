package db

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// GetCvesByMicrosoftKBID :
func (r *RDBDriver) GetCvesByMicrosoftKBID(osName string, installedProducts []string, applied []string, unapplied []string) (map[string]models.MicrosoftCVE, error) {
	applied, unapplied, err := r.extractKBIDs(applied, unapplied)
	if err != nil {
		return nil, xerrors.Errorf("Failed to extract KBIDs. err: %w", err)
	}

	var productsFromKBID []string
	if kbids := append(applied, unapplied...); len(kbids) > 0 {
		if err := r.conn.
			Model(&models.MicrosoftProduct{}).
			Distinct("microsoft_products.name").
			Joins("JOIN microsoft_kbs ON microsoft_kbs.microsoft_product_id = microsoft_products.id AND microsoft_kbs.article IN ?", kbids).
			Find(&productsFromKBID).Error; err != nil {
			return nil, xerrors.Errorf("Failed to detect Products. err: %w", err)
		}
	}

	products := getProductLists(osName, append(installedProducts, productsFromKBID...))

	detected := map[string]models.MicrosoftCVE{}

	var q *gorm.DB
	if len(products) > 0 {
		q = r.conn.Preload("Products", "name IN ?", products)
	} else {
		q = r.conn.Preload("Products")
	}
	cs := []models.MicrosoftCVE{}
	if err := q.
		Preload("Products.ScoreSet").
		Preload("Products.KBs").
		FindInBatches(&cs, 500, func(tx *gorm.DB, batch int) error {
			for _, c := range cs {
				ps := []models.MicrosoftProduct{}
				for _, p := range c.Products {
					if len(p.KBs) == 0 {
						ps = append(ps, p)
						continue
					}

					kbs := []models.MicrosoftKB{}
					for _, kb := range p.KBs {
						if slices.Contains(applied, kb.Article) {
							kbs = []models.MicrosoftKB{}
							break
						}
						if slices.Contains(unapplied, kb.Article) {
							kbs = append(kbs, kb)
						}
					}
					if len(kbs) > 0 {
						p.KBs = kbs
						ps = append(ps, p)
					}
				}
				if len(ps) > 0 {
					c.Products = ps
					detected[c.CveID] = c
				}
			}
			return nil
		}).Error; err != nil {
		return nil, err
	}

	return detected, nil
}

func (r *RDBDriver) extractKBIDs(applied []string, unapplied []string) ([]string, []string, error) {
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

var (
	winDesktopPattern = regexp.MustCompile(`(.+ on )?(Microsoft )?Windows (NT|98|20(00|03)|Millennium|XP|Vista|7|RT|8|10|11)`)
	winServerPattern  = regexp.MustCompile(`(.+ on )?(Microsoft )?Windows Server,? (20(03|08|12|16|19|22)|Version)`)
)

func getProductLists(osName string, products []string) []string {
	var ps []string
	if osName == "" {
		return util.Unique(products)
	}

	ps = append(ps, osName)

	isR2 := false
	isServerCore := false
	if winServerPattern.MatchString(osName) {
		if strings.Contains(osName, "R2") {
			isR2 = true
		}
		if strings.Contains(osName, "(Server Core installation)") {
			isServerCore = true
		}
	}
	for _, p := range products {
		if winDesktopPattern.MatchString(p) {
			if strings.Contains(p, osName) {
				ps = append(ps, p)
			}
		} else if winServerPattern.MatchString(p) {
			if strings.Contains(p, osName) {
				if !isR2 && strings.Contains(p, "R2") {
					continue
				}
				if !isServerCore && strings.Contains(p, "(Server Core installation)") {
					continue
				}
				ps = append(ps, p)
			}
		} else {
			ps = append(ps, p)
		}
	}
	return util.Unique(ps)
}

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
	bar := pb.StartNew(len(cves))
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
	bar := pb.StartNew(len(kbs))
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
