package notifier

import (
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/knqyf263/gost/config"
)

// EMailSender is interface of sending e-mail
type EMailSender interface {
	Send(subject, body string) error
}

type emailSender struct {
	conf config.SMTPConf
	send func(string, smtp.Auth, string, []string, []byte) error
}

// NewEMailSender creates emailSender
func NewEMailSender(config config.SMTPConf) EMailSender {
	return &emailSender{config, smtp.SendMail}
}

func (e *emailSender) Send(subject, body string) (err error) {
	emailConf := e.conf
	to := strings.Join(emailConf.To[:], ", ")
	cc := strings.Join(emailConf.Cc[:], ", ")
	mailAddresses := append(emailConf.To, emailConf.Cc...)
	if _, err := mail.ParseAddressList(strings.Join(mailAddresses[:], ", ")); err != nil {
		return fmt.Errorf("Failed to parse email addresses: %s", err)
	}

	headers := make(map[string]string)
	headers["From"] = emailConf.From
	headers["To"] = to
	headers["Cc"] = cc
	headers["Subject"] = subject
	headers["Date"] = time.Now().Format(time.RFC1123Z)
	headers["Content-Type"] = "text/plain; charset=utf-8"

	var header string
	for k, v := range headers {
		header += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message := fmt.Sprintf("%s\r\n%s", header, body)

	smtpServer := net.JoinHostPort(emailConf.SMTPAddr, emailConf.SMTPPort)
	err = e.send(
		smtpServer,
		smtp.PlainAuth(
			"",
			emailConf.User,
			emailConf.Password,
			emailConf.SMTPAddr,
		),
		emailConf.From,
		mailAddresses,
		[]byte(message),
	)
	if err != nil {
		return fmt.Errorf("Failed to send emails: %s", err)
	}
	return nil
}
