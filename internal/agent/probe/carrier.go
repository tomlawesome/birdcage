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
// that plants a marker for it, or -- for vnc, ntp and portscan -- that
// does whatever that service's own grade needs instead (see each
// carrier's own doc comment). A service named by a target but absent
// here -- other than the notProbeable set below -- gets StatusNoCarrier
// rather than a guess, per #46's instruction: "skip it and return a
// clearly-labelled outcome rather than guessing."
//
// vnc, ntp and portscan are #46 slice 2 (notes 19854/19855/19897):
// vnc.go's challenge-marked HMAC, and attribution.go's ntp/portscan
// touches for birdcage's own exactly-one correlation
// (internal/store/selftest_attribution.go).
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
	"vnc":      probeVNC,
	"ntp":      probeNTP,
	"portscan": probePortscan,
}

// notProbeable are the services #46 rules out of scope for this build:
// smb needs a real Samba audit VFS this build cannot provide (a deploy
// dependency, not a protocol limit -- see note 19797), and llmnr's own
// detector (#86) is a separate, not-yet-designed feature -- OpenCanary's
// own llmnr module stays permanently disabled per notes 20752/20767, so
// there is currently no live target for a carrier to trigger at all. A
// target naming one of these is reported as StatusNotProbeable; nothing
// is attempted, and it is never treated as StatusNoCarrier, so a log
// reader can tell "ruled out" apart from "this build doesn't know how
// yet."
var notProbeable = map[string]bool{
	"smb":   true,
	"llmnr": true,
}
