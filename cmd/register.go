package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/inconshreveable/log15"
	runewidth "github.com/mattn/go-runewidth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/config"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/models"
	"github.com/vulsio/gost/util"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register CVEs to monitor",
	Long:  `Register CVEs to monitor`,
	RunE:  executeRegister,
}

func init() {
	RootCmd.AddCommand(registerCmd)

	registerCmd.PersistentFlags().String("select-cmd", "fzf", "Select command")
	_ = viper.BindPFlag("select-cmd", registerCmd.PersistentFlags().Lookup("select-cmd"))

	registerCmd.PersistentFlags().String("select-option", "--reverse", "Select command options")
	_ = viper.BindPFlag("select-option", registerCmd.PersistentFlags().Lookup("select-option"))

	registerCmd.PersistentFlags().String("select-after", "", "Show CVEs after the specified date (e.g. 2017-01-01) (default: 30 days ago)")
	_ = viper.BindPFlag("select-after", registerCmd.PersistentFlags().Lookup("select-after"))
}

func executeRegister(_ *cobra.Command, _ []string) (err error) {
	if err := util.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	log15.Info("Validate command-line options")
	afterOption := viper.GetString("select-after")
	var after time.Time
	if afterOption != "" {
		if after, err = time.Parse("2006-01-02", afterOption); err != nil {
			return xerrors.Errorf("Failed to parse --select-after. err: %w", err)
		}
	} else {
		now := time.Now()
		after = now.Add(time.Duration(-1) * 24 * 30 * time.Hour)
	}

	log15.Info("Load toml config")
	var conf config.Config
	filename := "config.toml"
	if _, err = os.Stat(filename); err == nil {
		_, err = toml.DecodeFile("config.toml", &conf)
		if err != nil {
			return err
		}
	} else {
		conf.Redhat = map[string]config.RedhatWatchCve{}
	}

	log15.Info("Initialize Database")
	driver, err := db.NewDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"), db.Option{})
	if err != nil {
		if errors.Is(err, db.ErrDBLocked) {
			return xerrors.Errorf("Failed to open DB. Close DB connection before fetching. err: %w", err)
		}
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to register command. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	log15.Info("Select all RedHat CVEs")
	allRedhat, err := driver.GetAfterTimeRedhat(after)
	if err != nil {
		return err
	}

	allRedhatText := []string{}
	for _, redhat := range allRedhat {
		if redhat.Name == "" {
			continue
		}
		allRedhatText = append(allRedhatText, fmt.Sprintf("%-16s | %-10s | %-3s | %-24s | %s", redhat.Name, redhat.ThreatSeverity,
			redhat.Cvss3.Cvss3BaseScore, runewidth.Truncate(redhat.GetPackages(","), 20, "..."), runewidth.Truncate(redhat.GetDetail(""), 120, "...")))
	}
	selectedLine, err := filter(allRedhatText)
	if err != nil {
		return err
	}

	cves := []string{}
	for _, line := range selectedLine {
		split := strings.Split(line, "|")
		if len(split) < 2 {
			continue
		}
		cves = append(cves, strings.TrimSpace(split[0]))
	}

	log15.Info("Register CVEs to watch list")
	for _, cve := range cves {
		_, ok := conf.Redhat[cve]
		if !ok {
			conf.Redhat[cve] = config.RedhatWatchCve{}
		}
	}
	if err = save(conf); err != nil {
		return xerrors.Errorf("Failed to save the selected CVEs. err: %w", err)
	}

	return err
}

func run(command string, r io.Reader, w io.Writer) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	cmd.Stderr = os.Stderr
	cmd.Stdout = w
	cmd.Stdin = r
	return cmd.Run()
}

func filter(cves []string) (results []string, err error) {
	var buf bytes.Buffer
	selectCmd := fmt.Sprintf("%s %s",
		viper.GetString("select-cmd"), viper.GetString("select-option"))
	err = run(selectCmd, strings.NewReader(strings.Join(cves, "\n")), &buf)
	if err != nil {
		return nil, nil
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	return lines, nil
}

func save(conf config.Config) error {
	confFile := "config.toml"
	f, err := os.Create(confFile)
	if err != nil {
		return xerrors.Errorf("Failed to save config file. err: %w", err)
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(conf)
}
