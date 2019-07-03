module github.com/knqyf263/gost

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/cheggaaa/pb v2.0.7+incompatible
	github.com/go-redis/redis v6.15.2+incompatible
	github.com/grokify/html-strip-tags-go v0.0.0-20190424092004-025bd760b278
	github.com/inconshreveable/log15 v0.0.0-20180818164646-67afb5ed74ec
	github.com/jinzhu/gorm v1.9.10
	github.com/labstack/echo v3.3.10+incompatible
	github.com/labstack/gommon v0.2.9
	github.com/mattn/go-runewidth v0.0.4
	github.com/mattn/go-sqlite3 v1.10.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/moul/http2curl v1.0.0 // indirect
	github.com/parnurzeal/gorequest v0.2.15
	github.com/pkg/errors v0.8.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	github.com/tealeg/xlsx v1.0.3
	gopkg.in/VividCortex/ewma.v1 v1.1.1 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/cheggaaa/pb.v2 v2.0.7 // indirect
	gopkg.in/fatih/color.v1 v1.7.0 // indirect
	gopkg.in/mattn/go-colorable.v0 v0.0.0-00010101000000-000000000000 // indirect
	gopkg.in/mattn/go-isatty.v0 v0.0.0-00010101000000-000000000000 // indirect
	gopkg.in/mattn/go-runewidth.v0 v0.0.4 // indirect
)

replace gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.0

replace gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.6
