package notifier

import (
	"encoding/json"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/parnurzeal/gorequest"
	"github.com/vulsio/gost/config"
)

type message struct {
	Text      string `json:"text"`
	Username  string `json:"username"`
	IconEmoji string `json:"icon_emoji"`
	Channel   string `json:"channel"`
}

// SendSlack sends a message to Slack
func SendSlack(txt string, conf config.SlackConf) error {
	msg := message{
		Text:      "```" + txt + "```",
		Username:  conf.AuthUser,
		IconEmoji: conf.IconEmoji,
		Channel:   conf.Channel,
	}
	return send(msg, conf)
}

func send(msg message, conf config.SlackConf) error {
	count, retryMax := 0, 10

	bytes, _ := json.Marshal(msg)
	jsonBody := string(bytes)

	f := func() (err error) {
		resp, body, errs := gorequest.New().Proxy(viper.GetString("http-proxy")).Post(conf.HookURL).Send(string(jsonBody)).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			count++
			if count == retryMax {
				return nil
			}
			return xerrors.Errorf("HTTP POST error: %v, url: %s, resp: %v, body: %s", errs, conf.HookURL, resp, body)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log15.Warn("Error", "err", err)
		log15.Warn("Retrying", "in", t)
	}
	boff := backoff.NewExponentialBackOff()
	if err := backoff.RetryNotify(f, boff, notify); err != nil {
		return xerrors.Errorf("HTTP error: %w", err)
	}
	if count == retryMax {
		return xerrors.Errorf("Retry count exceeded")
	}
	return nil
}
