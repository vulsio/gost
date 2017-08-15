package config

type Config struct {
	Redhat map[string]RedhatWatchCve `toml:"redhat"`
	EMail  SMTPConf
	Slack  SlackConf
}

type RedhatWatchCve struct {
	ThreatSeverity  bool `toml:"threat_severity"`
	Bugzilla        bool `toml:"bugzilla"`
	Cvss            bool `toml:"cvss"`
	Cvss3           bool `toml:"cvss3"`
	Statement       bool `toml:"statement"`
	Acknowledgement bool `toml:"acknowledgement"`
	Mitigation      bool `toml:"mitigation"`
	AffectedRelease bool `toml:"affected_release"`
	PackageState    bool `toml:"package_state"`
	Reference       bool `toml:"reference"`
	Details         bool `toml:"details"`
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
