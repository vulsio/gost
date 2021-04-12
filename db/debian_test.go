package db

import (
	"fmt"
	"reflect"
	"testing"
)

func TestRDBDriver_getCvesDebianWithFixStatus1(t *testing.T) {
	type args struct {
		major     string
		fixStatus string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				major:     "10",
				fixStatus: "open",
			},
		},
		{
			name: "",
			args: args{
				major:     "9",
				fixStatus: "resolved",
			},
		},
	}

	new := RDBDriver{name: "new"}
	locked, err := new.OpenDB(dialectSqlite3, "../gost.sqlite3", false)
	if locked {
		t.Errorf("Failed to open sqlite3, %+v", err)
	} else if err != nil {
		t.Errorf("Failed to open sqlite3, %+v", err)
	}

	type Result struct{ PackageName string }
	var results []Result
	if err := new.conn.Raw("select distinct(package_name) from debian_packages").Scan(&results).Error; err != nil {
		t.Errorf("Failed to open sqlite3, %+v", err)
	}
	defer new.CloseDB()
	fmt.Printf("%d pkgs\n", len(results))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, r := range results {
				mNew := new.getCvesDebianWithFixStatus1(tt.args.major, r.PackageName, tt.args.fixStatus)
				mOld := new.getCvesDebianWithFixStatus(tt.args.major, r.PackageName, tt.args.fixStatus)
				if !reflect.DeepEqual(mOld, mNew) {
					t.Errorf("old = %v, new %v", mOld, mNew)
				}
			}
		})
	}
}
