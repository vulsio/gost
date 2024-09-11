package models

import (
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

// MicrosoftVulnerability :
type MicrosoftVulnerability struct {
	CveID         string   `json:"CVEID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	FAQs          []string `json:"FAQs"`
	Tag           string   `json:"Tag"`
	CNA           string   `json:"CNA"`
	ExploitStatus string   `json:"ExploitStatus"`
	Mitigation    string   `json:"Mitigation"`
	Workaround    string   `json:"Workaround"`
	Products      []struct {
		ProductID string `json:"ProductID"`
		Name      string `json:"Name"`
		Impact    string `json:"Impact"`
		Severity  string `json:"Severity"`
		ScoreSet  struct {
			BaseScore     string `json:"BaseScore"`
			TemporalScore string `json:"TemporalScore"`
			Vector        string `json:"Vector"`
		} `json:"ScoreSet,omitempty"`
		KBs []struct {
			Article         string `json:"Article"`
			RestartRequired string `json:"RestartRequired"`
			SubType         string `json:"SubType"`
			FixedBuild      string `json:"FixedBuild"`
			ArticleURL      string `json:"ArticleURL"`
			DownloadURL     string `json:"DownloadURL"`
		} `json:"KBs,omitempty"`
	} `json:"Products"`
	URL             string `json:"URL"`
	Acknowledgments []struct {
		Name string `json:"Name"`
	} `json:"Acknowledgments"`
	Revisions []revision `json:"Revisions"`
}

type revision struct {
	Number      string `json:"Number"`
	Date        string `json:"Date"`
	Description string `json:"Description"`
}

// MicrosoftSupercedence :
type MicrosoftSupercedence struct {
	KBID         string `json:"KBID"`
	UpdateID     string `json:"UpdateID"`
	Product      string `json:"Product"`
	Supersededby struct {
		KBIDs     []string `json:"KBIDs"`
		UpdateIDs []string `json:"UpdateIDs"`
	} `json:"Supersededby"`
}

// MicrosoftCVE :
type MicrosoftCVE struct {
	ID              int64              `json:"-"`
	CveID           string             `json:"cve_id" gorm:"type:varchar(255);index:idx_microsoft_cves_cveid"`
	Title           string             `json:"title" gorm:"type:varchar(255)"`
	Description     string             `json:"description" gorm:"type:text"`
	FAQ             string             `json:"faq" gorm:"type:text"`
	Tag             string             `json:"tag" gorm:"type:varchar(255)"`
	CNA             string             `json:"cna" gorm:"type:varchar(255)"`
	ExploitStatus   string             `json:"exploit_status" gorm:"type:varchar(255)"`
	Mitigation      string             `json:"mitigation" gorm:"type:text"`
	Workaround      string             `json:"workaround" gorm:"type:text"`
	Products        []MicrosoftProduct `json:"products"`
	URL             string             `json:"url" gorm:"type:varchar(255)"`
	Acknowledgments string             `json:"acknowledgments" gorm:"type:text"`
	PublishDate     time.Time          `json:"publish_date"`
	LastUpdateDate  time.Time          `json:"last_update_date"`
}

// MicrosoftProduct :
type MicrosoftProduct struct {
	ID             int64             `json:"-"`
	MicrosoftCVEID int64             `json:"-" gorm:"index:idx_microsoft_product_microsoft_cve_id"`
	ProductID      string            `json:"product_id" gorm:"type:varchar(255)"`
	Name           string            `json:"name" gorm:"type:varchar(255)"`
	Impact         string            `json:"impact" gorm:"type:varchar(255)"`
	Severity       string            `json:"severity" gorm:"type:varchar(255)"`
	ScoreSet       MicrosoftScoreSet `json:"score_set"`
	KBs            []MicrosoftKB     `json:"kbs"`
}

// MicrosoftScoreSet :
type MicrosoftScoreSet struct {
	ID                 int64  `json:"-"`
	MicrosoftProductID int64  `json:"-" gorm:"index:idx_microsoft_score_set_microsoft_product_id"`
	BaseScore          string `json:"base_score" gorm:"type:varchar(255)"`
	TemporalScore      string `json:"temporal_score" gorm:"type:varchar(255)"`
	Vector             string `json:"vector" gorm:"type:varchar(255)"`
}

// MicrosoftKB :
type MicrosoftKB struct {
	ID                 int64  `json:"-"`
	MicrosoftProductID int64  `json:"-" gorm:"index:idx_microsoft_kb_microsoft_product_id"`
	Article            string `json:"article" gorm:"type:varchar(255);index:idx_microsoft_kb_article"`
	RestartRequired    string `json:"restart_required" gorm:"type:varchar(255)"`
	SubType            string `json:"sub_type" gorm:"type:varchar(255)"`
	FixedBuild         string `json:"fixed_build" gorm:"type:varchar(255)"`
	ArticleURL         string `json:"article_url" gorm:"type:varchar(255)"`
	DownloadURL        string `json:"download_url" gorm:"type:varchar(255)"`
}

// MicrosoftKBRelation :
type MicrosoftKBRelation struct {
	ID           int64  `json:"-"`
	KBID         string `json:"kbid" gorm:"type:varchar(255);index:idx_microsoft_relation_kb_id"`
	SupersededBy []MicrosoftSupersededBy
}

// MicrosoftSupersededBy :
type MicrosoftSupersededBy struct {
	ID                    int64  `json:"-"`
	MicrosoftKBRelationID int64  `json:"-" gorm:"index:idx_microsoft_superseded_by_microsoft_kb_relation_id"`
	KBID                  string `json:"kbid" gorm:"type:varchar(255);index:idx_microsoft_superseded_by_kb_id"`
}

// ConvertMicrosoft :
func ConvertMicrosoft(vulns []MicrosoftVulnerability, supercedences []MicrosoftSupercedence) ([]MicrosoftCVE, []MicrosoftKBRelation) {
	cves := []MicrosoftCVE{}
	for _, v := range vulns {
		cve := MicrosoftCVE{
			CveID:          v.CveID,
			Title:          v.Title,
			Description:    v.Description,
			FAQ:            strings.Join(v.FAQs, "\n"),
			Tag:            v.Tag,
			CNA:            v.CNA,
			ExploitStatus:  v.ExploitStatus,
			Mitigation:     v.Mitigation,
			Workaround:     v.Workaround,
			URL:            v.URL,
			PublishDate:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
			LastUpdateDate: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
		}

		for _, p := range v.Products {
			product := MicrosoftProduct{
				ProductID: p.ProductID,
				Name:      p.Name,
				Impact:    p.Impact,
				Severity:  p.Severity,
				KBs:       []MicrosoftKB{},
			}
			if p.ScoreSet.BaseScore != "" || p.ScoreSet.TemporalScore != "" || p.ScoreSet.Vector != "" {
				product.ScoreSet = MicrosoftScoreSet{
					BaseScore:     p.ScoreSet.BaseScore,
					TemporalScore: p.ScoreSet.TemporalScore,
					Vector:        p.ScoreSet.Vector,
				}
			}
			for _, kb := range p.KBs {
				product.KBs = append(product.KBs, MicrosoftKB{
					Article:         kb.Article,
					RestartRequired: kb.RestartRequired,
					SubType:         kb.SubType,
					FixedBuild:      kb.FixedBuild,
					ArticleURL:      kb.ArticleURL,
					DownloadURL:     kb.DownloadURL,
				})
			}
			cve.Products = append(cve.Products, product)
		}

		as := []string{}
		for _, a := range v.Acknowledgments {
			as = append(as, a.Name)
		}
		cve.Acknowledgments = strings.Join(as, ";")

		revs := []time.Time{}
		for _, r := range v.Revisions {
			t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(r.Date, "Z"))
			if err == nil {
				revs = append(revs, t)
			}
		}
		slices.SortFunc(revs, func(i, j time.Time) int {
			if i.Before(j) {
				return -1
			}
			if i.After(j) {
				return +1
			}
			return 0
		})
		if len(revs) > 0 {
			cve.PublishDate = revs[0]
			cve.LastUpdateDate = revs[len(revs)-1]
		}

		cves = append(cves, cve)
	}

	relations := []MicrosoftKBRelation{}
	for _, s := range supercedences {
		r := MicrosoftKBRelation{
			KBID: s.KBID,
		}
		for _, skbid := range s.Supersededby.KBIDs {
			r.SupersededBy = append(r.SupersededBy, MicrosoftSupersededBy{
				KBID: skbid,
			})
		}
		relations = append(relations, r)
	}

	return cves, relations
}
