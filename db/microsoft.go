package db

import (
	"errors"
	"fmt"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gorm.io/gorm"

	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// GetCveIDsByMicrosoftKBID :
func (r *RDBDriver) GetCveIDsByMicrosoftKBID(applied []string, unapplied []string) (map[string][]string, error) {
	kbIDs, err := r.getUnAppliedKBIDs(applied, unapplied)
	if err != nil {
		return nil, xerrors.Errorf("Failed to get UnApplied KBIDs. err: %w", err)
	}

	kbCVEIDs := map[string][]string{}
	for _, kbID := range kbIDs {
		msIDs := []string{}
		if err := r.conn.
			Model(&models.MicrosoftKBID{}).
			Distinct("microsoft_cve_id").
			Where("kb_id = ?", kbID).
			Find(&msIDs).Error; err != nil {
			return nil, xerrors.Errorf("Failed to get MicrosoftCVEID by KBID. err: %w", err)
		}
		if len(msIDs) == 0 {
			kbCVEIDs[kbID] = []string{}
			continue
		}

		cveIDs := []string{}
		if err := r.conn.
			Model(&models.MicrosoftCVE{}).
			Distinct("cve_id").
			Where("id IN ?", msIDs).
			Find(&cveIDs).Error; err != nil {
			return nil, xerrors.Errorf("Failed to get CVEID by MicrosoftCVEID. err: %w", err)
		}
		kbCVEIDs[kbID] = cveIDs
	}
	return kbCVEIDs, nil
}

func (r *RDBDriver) getUnAppliedKBIDs(applied []string, unapplied []string) ([]string, error) {
	uniqUnappliedKBIDs := map[string]struct{}{}
	if len(applied) > 0 {
		relations := []models.MicrosoftKBRelation{}

		if err := r.conn.
			Preload("SupersededBy").
			Where("kb_id IN ?", applied).
			Find(&relations).Error; err != nil {
			return nil, xerrors.Errorf("Failed to get KB Relation by applied KBID: %q. err: %w", applied, err)
		}

		for _, relation := range relations {
			isInApplied := false
			for _, supersededby := range relation.SupersededBy {
				if util.StringInSlice(supersededby.KBID, applied) {
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

	if len(unapplied) > 0 {
		relations := []models.MicrosoftKBRelation{}

		if err := r.conn.
			Preload("SupersededBy").
			Where("kb_id IN ?", unapplied).
			Find(&relations).Error; err != nil {
			return nil, xerrors.Errorf("Failed to get KB Relation by unapplied KBID: %q. err: %w", unapplied, err)
		}

		for _, relation := range relations {
			uniqUnappliedKBIDs[relation.KBID] = struct{}{}
			for _, supersededby := range relation.SupersededBy {
				uniqUnappliedKBIDs[supersededby.KBID] = struct{}{}
			}
		}
	}

	unappliedKBIDs := []string{}
	for kbid := range uniqUnappliedKBIDs {
		unappliedKBIDs = append(unappliedKBIDs, kbid)
	}

	return unappliedKBIDs, nil
}

// GetMicrosoft :
func (r *RDBDriver) GetMicrosoft(cveID string) (*models.MicrosoftCVE, error) {
	c := models.MicrosoftCVE{}
	if err := r.conn.Where(&models.MicrosoftCVE{CveID: cveID}).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		log15.Error("Failed to get Microsoft", "err", err)
		return nil, err
	}

	if err := r.conn.Model(&c).Association("MicrosoftProductStatuses").Find(&c.MicrosoftProductStatuses); err != nil {
		return nil, err
	}
	if len(c.MicrosoftProductStatuses) == 0 {
		c.MicrosoftProductStatuses = nil
	} else {
		for i := range c.MicrosoftProductStatuses {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("MicrosoftProductStatus:%d", i)).Find(&c.MicrosoftProductStatuses[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Impact'", c.ID).Find(&c.Impact).Error; err != nil {
		return nil, err
	}
	if len(c.Impact) == 0 {
		c.Impact = nil
	} else {
		for i := range c.Impact {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("Impact:%d", i)).Find(&c.Impact[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Severity'", c.ID).Find(&c.Severity).Error; err != nil {
		return nil, err
	}
	if len(c.Severity) == 0 {
		c.Severity = nil
	} else {
		for i := range c.Severity {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("Severity:%d", i)).Find(&c.Severity[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Vendor Fix'", c.ID).Find(&c.VendorFix).Error; err != nil {
		return nil, err
	}
	if len(c.VendorFix) == 0 {
		c.VendorFix = nil
	} else {
		for i := range c.VendorFix {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("VendorFix:%d", i)).Find(&c.VendorFix[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Where("microsoft_cve_id = ? AND attr_type = 'None Available'", c.ID).Find(&c.NoneAvailable).Error; err != nil {
		return nil, err
	}
	if len(c.NoneAvailable) == 0 {
		c.NoneAvailable = nil
	} else {
		for i := range c.NoneAvailable {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("NoneAvailable:%d", i)).Find(&c.NoneAvailable[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Where("microsoft_cve_id = ? AND attr_type = 'Will Not Fix'", c.ID).Find(&c.WillNotFix).Error; err != nil {
		return nil, err
	}
	if len(c.WillNotFix) == 0 {
		c.WillNotFix = nil
	} else {
		for i := range c.WillNotFix {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("WillNotFix:%d", i)).Find(&c.WillNotFix[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Model(&c).Association("ScoreSets").Find(&c.ScoreSets); err != nil {
		return nil, err
	}
	if len(c.ScoreSets) == 0 {
		c.ScoreSets = nil
	} else {
		for i := range c.ScoreSets {
			if err := r.conn.Where("microsoft_cve_id = ? AND category = ?", c.ID, fmt.Sprintf("MicrosoftScoreSet:%d", i)).Find(&c.ScoreSets[i].Products).Error; err != nil {
				return nil, err
			}
		}
	}

	if err := r.conn.Model(&c).Association("References").Find(&c.References); err != nil {
		return nil, err
	}
	if len(c.References) == 0 {
		c.References = nil
	}

	if err := r.conn.Model(&c).Association("KBIDs").Find(&c.KBIDs); err != nil {
		return nil, err
	}
	if len(c.KBIDs) == 0 {
		c.KBIDs = nil
	}

	return &c, nil
}

// GetMicrosoftMulti :
func (r *RDBDriver) GetMicrosoftMulti(cveIDs []string) (map[string]models.MicrosoftCVE, error) {
	m := map[string]models.MicrosoftCVE{}
	for _, cveID := range cveIDs {
		cve, err := r.GetMicrosoft(cveID)
		if err != nil {
			return nil, err
		}
		if cve != nil {
			m[cveID] = *cve
		}
	}
	return m, nil
}

// InsertMicrosoft :
func (r *RDBDriver) InsertMicrosoft(cves []models.MicrosoftCVE, _ []models.MicrosoftProduct, kbRelations []models.MicrosoftKBRelation) error {
	log15.Info("Inserting cves", "cves", len(cves))
	if err := r.deleteAndInsertMicrosoft(cves); err != nil {
		return xerrors.Errorf("Failed to insert Microsoft CVE data. err: %w", err)
	}
	log15.Info("Insert KB Relation", "kbRelation", len(kbRelations))
	if err := r.deleteAndInsertMicrosoftKBRelation(kbRelations); err != nil {
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
	for _, table := range []interface{}{models.MicrosoftScoreSet{}, models.MicrosoftReference{}, models.MicrosoftKBID{}, models.MicrosoftRemediation{}, models.MicrosoftThreat{}, models.MicrosoftProductStatus{}, models.MicrosoftProduct{}, models.MicrosoftCVE{}} {
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

// GetUnfixedCvesMicrosoft :
func (r *RDBDriver) GetUnfixedCvesMicrosoft(_, _ string, _ ...bool) (map[string]models.MicrosoftCVE, error) {
	return map[string]models.MicrosoftCVE{}, nil
}
