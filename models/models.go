package models

import (
	"time"

	"gorm.io/gorm"
)

// LatestSchemaVersion manages the Schema version used in the latest Gost.
const LatestSchemaVersion = 2

// FetchMeta has meta information about fetched security tracker
type FetchMeta struct {
	gorm.Model      `json:"-"`
	GostRevision    string
	SchemaVersion   uint
	LastFetchedDate time.Time
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}
