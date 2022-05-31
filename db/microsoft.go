package db

import (
	"errors"
	"fmt"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
)

// GetCvesByMicrosoftKBID :
func (r *RDBDriver) GetCvesByMicrosoftKBID(products []string, applied []string, unapplied []string) (map[string]models.MicrosoftCVE, error) {
	applied, unapplied, err := r.extractKBIDs(applied, unapplied)
	if err != nil {
		return nil, xerrors.Errorf("Failed to extract KBIDs. err: %w", err)
	}

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

			tx.Save(&cs)

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
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftKB{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftKB. err: %s", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftScoreSet{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftScoreSet. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftProduct{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftProduct. err: %w", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftCVE{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftCVE. err: %w", err)
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
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftKBRelation{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftKBRelation. err: %s", err)
	}
	if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(models.MicrosoftSupersededBy{}).Error; err != nil {
		return xerrors.Errorf("Failed to delete MicrosoftSupersededBy. err: %s", err)
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
