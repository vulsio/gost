package convert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// ConvertCmd :
var ConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert the data of vulnerabilities",
	Long:  `Convert the data of vulnerabilities`,
}

func init() {
	// subcommands
	ConvertCmd.AddCommand(convertRedHatCmd)
	ConvertCmd.AddCommand(convertDebianCmd)
	ConvertCmd.AddCommand(convertUbuntuCmd)

	// flags
	ConvertCmd.PersistentFlags().String("vuln-dir", util.GetDefaultVulnDir(), "root directory to output Vuln data")
	ConvertCmd.PersistentFlags().String("http-proxy", "", "http://proxy-url:port")
}

func setLastUpdatedDate(key string) error {
	lastUpdatedFilePath := filepath.Join(filepath.Dir(filepath.Clean(viper.GetString("vuln-dir"))), "last_updated.json")
	lastUpdated := map[string]time.Time{}
	if f, err := os.Open(lastUpdatedFilePath); err != nil {
		if !os.IsNotExist(err) {
			return xerrors.Errorf("Failed to open last updated file. err: %w", err)
		}
	} else {
		if err := json.NewDecoder(f).Decode(&lastUpdated); err != nil {
			_ = f.Close() // ignore error; Write error takes precedence
			return xerrors.Errorf("Failed to decode last updated file. err: %w", err)
		}
		if err := f.Close(); err != nil {
			return xerrors.Errorf("Failed to close last updated file. err: %w", err)
		}
	}
	lastUpdated[key] = time.Now()

	f, err := os.Create(lastUpdatedFilePath)
	if err != nil {
		return xerrors.Errorf("Failed to open last updated file. err: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err = enc.Encode(lastUpdated); err != nil {
		_ = f.Close() // ignore error; Write error takes precedence
		return xerrors.Errorf("Failed to encode last updated file. err: %w", err)
	}
	if err := f.Close(); err != nil {
		return xerrors.Errorf("Failed to close last updated file. err: %w", err)
	}

	return nil
}
