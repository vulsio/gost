package config

type Config struct {
	Redhat map[string]WatchCve `toml:"redhat"`
	EMail  SMTPConf
	Slack  SlackConf
}

// type RedhatCve struct {
// 	Cve []WatchCve `toml:"cve"`
// }

type WatchCve struct {
	CveId           string `toml:"cveid"`
	ThreatSeverity  bool   `toml:"threat_severity"`
	Bugzilla        bool
	Cvss            bool
	Cvss3           bool
	Statement       bool
	Acknowledgement bool
	Mitigation      bool
	AffectedRelease bool `toml:"affected_release"`
	PackageState    bool `toml:"package_state"`
	Reference       bool
	Details         bool
}

// SMTPConf is smtp config
type SMTPConf struct {
	SMTPAddr string
	SMTPPort string `valid:"port"`

	User          string
	Password      string
	From          string
	To            []string
	Cc            []string
	SubjectPrefix string

	UseThisTime bool
}

// SlackConf is slack config
type SlackConf struct {
	HookURL   string `valid:"url"`
	Channel   string `json:"channel"`
	IconEmoji string `json:"icon_emoji"`
	AuthUser  string `json:"username"`

	NotifyUsers []string
	Text        string `json:"text"`

	UseThisTime bool
}
