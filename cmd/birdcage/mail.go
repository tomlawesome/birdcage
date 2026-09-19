package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tomlawesome/birdcage/internal/mail"
)

// loadMailConfig reads issue #55's outbound-mail configuration from the
// environment and logs what it found -- never the password, and never
// anything derived from it.
//
// It refuses to start rather than returning: a half-configured mailer
// that only discovers it has no password at the moment a canary is
// cloned has failed at exactly the moment it was the point. That is the
// same posture internal/tlsconfig.Select takes for the dashboard
// listener and internal/ca.Load takes for the CA directory, applied to
// the one subsystem whose failure would otherwise be silent -- nothing
// on the dashboard goes red because a mail was never sent.
//
// With none of the variables set, mail is simply off: enabled is false,
// no listener or tick changes, and GET /api/mail reports
// "configured": false so the dashboard can say "mail off" rather than
// implying an alert would reach somebody.
func loadMailConfig(log *slog.Logger) (cfg mail.Config, enabled bool) {
	loaded, err := mail.Load(os.Getenv)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if !loaded.Enabled {
		log.Info(fmt.Sprintf("%s not set; outbound mail disabled", mail.EnvHost))
		return mail.Config{}, false
	}

	for _, w := range loaded.Warnings {
		log.Warn(w)
	}

	// Everything on this line is either the operator's own routing
	// information or a fixed word. The password is not logged, is not
	// summarised, and its length is not printed either -- a length is a
	// fact about a secret, and this file's whole job is to have none.
	transport := "implicit TLS"
	if loaded.Config.STARTTLS {
		transport = "STARTTLS"
	}
	passwordSource := mail.EnvPassword
	if os.Getenv(mail.EnvPasswordFile) != "" {
		passwordSource = mail.EnvPasswordFile
	}
	log.Info(fmt.Sprintf("%s=%s (%s, fully verified) %s=%s %s=%s %s=%s, password from %s",
		mail.EnvHost, loaded.Config.Host, transport,
		mail.EnvUsername, loaded.Config.Username,
		mail.EnvFrom, loaded.Config.From,
		mail.EnvTo, loaded.Config.To,
		passwordSource))

	return loaded.Config, true
}
