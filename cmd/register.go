package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/knqyf263/go-security-tracker/config"
	"github.com/knqyf263/go-security-tracker/db"
	"github.com/knqyf263/go-security-tracker/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: executeRegister,
}

func init() {
	RootCmd.AddCommand(registerCmd)

	registerCmd.PersistentFlags().String("select-cmd", "", "Select command (default: fzf)")
	viper.BindPFlag("select-cmd", registerCmd.PersistentFlags().Lookup("select-cmd"))
	viper.SetDefault("select-cmd", "fzf")

	registerCmd.PersistentFlags().String("select-option", "", "Select command options")
	viper.BindPFlag("select-option", registerCmd.PersistentFlags().Lookup("select-option"))
	viper.SetDefault("select-option", "--reverse")

	registerCmd.PersistentFlags().String("after", "", "Show CVEs after the specified date (e.g. 2017-01-01) (default: 30 days ago)")
	viper.BindPFlag("after", registerCmd.PersistentFlags().Lookup("after"))
	viper.SetDefault("after", "")
}

func executeRegister(cmd *cobra.Command, args []string) (err error) {
	log.Info("Validate command-line options")
	afterOption := viper.GetString("after")
	var after time.Time
	if afterOption != "" {
		if after, err = time.Parse("2006-01-02", afterOption); err != nil {
			return fmt.Errorf("Failed to parse --after. err: %s", err)
		}
	} else {
		now := time.Now()
		after = now.Add(time.Duration(-1) * 24 * 30 * time.Hour)
	}

	log.Info("Load toml config")
	var conf config.Config
	_, err = toml.DecodeFile("config.toml", &conf)
	if err != nil {
		return err
	}

	log.Info("Initialize Database")
	driver, err := db.InitDB(viper.GetString("dbtype"), viper.GetString("dbpath"), viper.GetBool("debug-sql"))
	if err != nil {
		return err
	}

	log.Info("Select all RedHat CVEs")
	allRedhat, err := driver.GetAfterTimeRedhat(after)
	if err != nil {
		return err
	}

	allRedhatText := []string{}
	for _, redhat := range allRedhat {
		// d := redhat.GetDetail("")
		// if d != "" {
		// 	fmt.Println(d)
		// }
		if redhat.Name == "" {
			continue
		}
		allRedhatText = append(allRedhatText, fmt.Sprintf("%-16s | %-10s | %-3s | %s", redhat.Name, redhat.ThreatSeverity,
			redhat.Cvss3.Cvss3BaseScore, redhat.GetDetail("")))
	}
	selectedLine, err := filter(allRedhatText)
	var cves []string
	for _, line := range selectedLine {
		split := strings.Split(line, "|")
		if len(split) < 2 {
			continue
		}
		cves = append(cves, strings.TrimSpace(split[0]))
	}

	for _, cve := range cves {
		_, ok := conf.Redhat[cve]
		if !ok {
			conf.Redhat[cve] = config.WatchCve{}
		}
	}
	if err = save(conf); err != nil {
		return fmt.Errorf("Failed to save the selected CVEs. err: %s", err)
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
	defer f.Close()
	if err != nil {
		return fmt.Errorf("Failed to save config file. err: %s", err)
	}
	return toml.NewEncoder(f).Encode(conf)
}
