package main

import (
	"context"

	"github.com/tomlawesome/birdcage/internal/agent/enrol"
	"github.com/tomlawesome/birdcage/internal/agent/enrolment"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var enrolLog = logging.New("enrol")

// ensureEnrolled is loadConfig's own first step, the same shared
// orchestration cmd/mockingbird/enrol.go calls -- factored into
// internal/agent/enrolment specifically so a second agent kind (#108)
// could reuse it rather than copy-pasting it. See that package's own doc
// comment for the full four-case decision table.
func ensureEnrolled(stateDir, birdcageURL, caPin, deployToken string) error {
	return enrolment.EnsureEnrolled(context.Background(), enrolment.Params{
		StateDir:           stateDir,
		BirdcageURL:        birdcageURL,
		CAPin:              caPin,
		DeployToken:        deployToken,
		DeployTokenEnvName: envDeployToken,
		RequiredFiles:      enrolStateFiles,
		NodeNoun:           "scanner",
		WriteState:         writeEnrolmentState,
		Log:                enrolLog,
	})
}

// writeEnrolmentState turns a successful enrolment's Hello/Credentials
// into the files this agent persists -- #47 "The flow" step 6, applied
// to the scanner kind. Nightjar has no log tailer and never displays
// the admin-approval or release addresses, so unlike
// cmd/mockingbird/enrol.go's own writeEnrolmentState it writes only what
// it actually reads back: the CA certificate, its mTLS identity, its
// bearer token, and the ingest listener's own address.
func writeEnrolmentState(hello enrol.Hello, creds enrol.Credentials) []enrolment.StateFile {
	return []enrolment.StateFile{
		{Name: caFileName, Data: hello.CAPEM},
		{Name: clientCertFileName, Data: creds.ClientCertPEM},
		{Name: clientKeyFileName, Data: creds.ClientKeyPEM},
		{Name: tokenFileName, Data: []byte(creds.CanaryToken)},
		{Name: ingestURLFileName, Data: []byte(hello.IngestURL)},
	}
}
