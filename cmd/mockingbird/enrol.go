package main

import (
	"context"

	"github.com/tomlawesome/birdcage/internal/agent/enrol"
	"github.com/tomlawesome/birdcage/internal/agent/enrolment"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var enrolLog = logging.New("enrol")

// ensureEnrolled is loadConfig's own first step: decide whether this
// boot needs to enrol before reading anything else out of stateDir, and
// run that enrolment if so. See internal/agent/enrolment.EnsureEnrolled
// for the full decision table (#47's four cases); this is mockingbird's
// own thin call into the shared orchestration, factored out (#108) so a
// second agent kind can reuse it rather than copy-pasting it.
func ensureEnrolled(stateDir, birdcageURL, caPin, deployToken string) error {
	return enrolment.EnsureEnrolled(context.Background(), enrolment.Params{
		StateDir:           stateDir,
		BirdcageURL:        birdcageURL,
		CAPin:              caPin,
		DeployToken:        deployToken,
		DeployTokenEnvName: envDeployToken,
		RequiredFiles:      enrolStateFiles,
		NodeNoun:           "canary",
		WriteState:         writeEnrolmentState,
		Log:                enrolLog,
	})
}

// writeEnrolmentState turns a successful enrolment's Hello/Credentials
// into the files this agent persists -- #47 "The flow" step 6. Which
// files a mockingbird canary writes is a fact about this agent kind, not
// about enrolment itself, so it stays here rather than in the shared
// internal/agent/enrolment package: ingestURLFileName,
// adminApprovalAddressFileName and releaseAddressFileName are written
// once, from POST /enrol/hello's own response, never configurable, never
// written any other way (see config.go's own doc comment on these
// constants).
//
// adminApprovalAddressFileName and releaseAddressFileName come first,
// before any of enrolStateFiles: they are outside the "already enrolled"
// presence test (config.go's own comment on enrolStateFiles), so
// writeState's restart-safety promise -- a crash partway through is
// reported as incomplete enrolment -- only holds if a crash can never
// land every enrolStateFiles entry while one of these is still missing.
// writeState writes sequentially, so keeping them first guarantees that.
// ingestURLFileName is now itself one of enrolStateFiles (loadConfig
// requires it), so it moves down among the rest of that group.
func writeEnrolmentState(hello enrol.Hello, creds enrol.Credentials, keyPEM []byte) []enrolment.StateFile {
	return []enrolment.StateFile{
		{Name: adminApprovalAddressFileName, Data: []byte(hello.AdminApprovalAddress)},
		{Name: releaseAddressFileName, Data: []byte(hello.ReleaseAddress)},
		{Name: ingestURLFileName, Data: []byte(hello.IngestURL)},
		{Name: caFileName, Data: hello.CAPEM},
		{Name: clientCertFileName, Data: creds.ClientCertPEM},
		{Name: clientKeyFileName, Data: keyPEM},
		{Name: tokenFileName, Data: []byte(creds.CanaryToken)},
	}
}
