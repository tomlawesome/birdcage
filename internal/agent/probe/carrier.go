package probe

import "context"

// carrierFunc opens a connection to address:port and plants marker
// where that service's OpenCanary module will log it. A non-nil error
// is a network or protocol-level failure -- dial refused, handshake
// timed out -- never a judgement about whether the target accepted any
// credential. Every carrierFunc is expected to honor ctx's deadline for
// every blocking call it makes.
type carrierFunc func(ctx context.Context, address string, port int, marker string) error

// carriers maps birdcage's service name (internal/opencanary's mapping,
// as carried on the wire by selftest.Target.Service) to the carrier
// that plants a marker for it. A service named by a target but absent
// here -- other than the notProbeable set below -- gets StatusNoCarrier
// rather than a guess, per #46's instruction: "skip it and return a
// clearly-labelled outcome rather than guessing."
//
// vnc is deliberately absent, despite being asked for: classic RFB only
// carries a credential as a challenge-response, DES-encrypted using the
// real VNC password as the key. Without that password the response is
// not attacker-chosen plaintext, so there is no field here that can
// carry an arbitrary marker -- the "where the protocol permits" carve-out
// in #46's own carrier list. Flagged for the owner rather than guessed
// at: see the build report for #46.
var carriers = map[string]carrierFunc{
	"ftp":      probeFTP,
	"telnet":   probeTelnet,
	"http":     probeHTTP,
	"snmp":     probeSNMP,
	"tftp":     probeTFTP,
	"sip":      probeSIP,
	"mysql":    probeMySQL,
	"mssql":    probeMSSQL,
	"postgres": probePostgres,
	"redis":    probeRedis,
	"rdp":      probeRDP,
	"ssh":      probeSSH,
}

// notProbeable are the services #46 rules out of scope entirely: their
// protocol either cannot be probed this way or cannot carry a marker,
// and what a canary should display for a self-test against them is an
// unanswered owner question. A target naming one of these is reported
// as StatusNotProbeable; nothing is attempted, and it is never treated
// as StatusNoCarrier, so a log reader can tell "ruled out" apart from
// "this build doesn't know how yet."
var notProbeable = map[string]bool{
	"smb":      true,
	"portscan": true,
	"llmnr":    true,
	"ntp":      true,
}
