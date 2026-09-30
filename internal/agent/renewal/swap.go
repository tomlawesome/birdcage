// Package renewal is the crash-safe write path a certificate renewal
// (ADR-0012 B2) uses to replace the agent's live client key and
// certificate on disk, and the recovery that completes or discards an
// interrupted one at the next boot.
//
// # Crash safety
//
// A renewal cannot just overwrite the live key file and then the live
// certificate file in place: each of those two writes is individually
// atomic (internal/agent/atomicfile.Write), but a crash between them
// would leave a live pair where the key is new and the certificate is
// still old (or vice versa) -- a mismatched pair that fails
// tls.X509KeyPair on the very next boot, with no way back except
// re-enrolment, over something that was never birdcage's fault.
//
// StageAndSwap avoids that by never touching the live files directly.
// It first writes the new key and the new certificate to two *staging*
// files (each write atomic on its own, via atomicfile.Write), then calls
// RecoverPendingSwap to move them into place. The staging files are the
// durable record of "this is the swap that should happen"; the live
// files are always either the old, fully-working pair or the new,
// fully-working pair -- never a mix -- because:
//
//   - If the process crashes before both staging files exist, at most
//     one of them is present. RecoverPendingSwap treats a lone staged key
//     with no staged certificate as an incomplete stage and discards it;
//     the live pair was never touched.
//   - Once both staging files exist, RecoverPendingSwap applies them to
//     the live files in a fixed order -- key, then certificate -- by
//     renaming each staging file over its live counterpart (each rename
//     itself atomic on the same filesystem). If the process crashes
//     between the two renames, the live key is already the new one and
//     the live certificate is still the old one; RecoverPendingSwap
//     called again (StageAndSwap's own last step, or the next boot's
//     recovery pass) sees only the certificate half still staged and
//     finishes that one rename. Re-running the whole function when
//     nothing (or everything) is left staged is a no-op.
//
// This does mean a crash in that narrow window between the two renames
// leaves the live key and certificate briefly out of sync with each
// other on disk -- but only ever key-ahead-of-certificate, and the
// recovery pass that must run before those files are read again
// (RecoverPendingSwap, called from the caller's own boot path) always
// finishes the swap deterministically rather than leaving it stuck.
package renewal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomlawesome/birdcage/internal/agent/atomicfile"
)

// stagingSuffix marks a file as the staged half of an in-flight
// certificate renewal, distinct from the live keyFileName/certFileName
// it is destined to replace.
const stagingSuffix = ".renew-new"

// StageAndSwap durably writes newKeyPEM and newCertPEM to staging files
// under stateDir, then applies them to the live keyFileName/certFileName
// via RecoverPendingSwap -- see the package doc comment for why this,
// and not writing the live files directly, is what makes a crash
// partway through recoverable.
func StageAndSwap(stateDir, keyFileName, certFileName string, newKeyPEM, newCertPEM []byte) error {
	stagingKey := filepath.Join(stateDir, keyFileName+stagingSuffix)
	stagingCert := filepath.Join(stateDir, certFileName+stagingSuffix)

	if err := atomicfile.Write(stagingKey, newKeyPEM, 0o600); err != nil {
		return fmt.Errorf("renewal: stage new key: %w", err)
	}
	if err := atomicfile.Write(stagingCert, newCertPEM, 0o600); err != nil {
		return fmt.Errorf("renewal: stage new certificate: %w", err)
	}
	return RecoverPendingSwap(stateDir, keyFileName, certFileName)
}

// RecoverPendingSwap completes or discards whatever StageAndSwap left
// staged under stateDir. Safe and cheap to call unconditionally at every
// boot, before reading keyFileName/certFileName: when nothing is staged
// it does nothing.
func RecoverPendingSwap(stateDir, keyFileName, certFileName string) error {
	stagingKey := filepath.Join(stateDir, keyFileName+stagingSuffix)
	stagingCert := filepath.Join(stateDir, certFileName+stagingSuffix)
	liveKey := filepath.Join(stateDir, keyFileName)
	liveCert := filepath.Join(stateDir, certFileName)

	keyStaged := exists(stagingKey)
	certStaged := exists(stagingCert)

	switch {
	case !keyStaged && !certStaged:
		// Nothing pending: either no renewal has ever run, or a previous
		// recovery pass already finished and cleaned up.
		return nil

	case keyStaged && certStaged:
		// Both halves durably staged -- the intended new pair. Apply key
		// first, then certificate, matching the order this function
		// itself expects to resume from if it is interrupted right here.
		if err := os.Rename(stagingKey, liveKey); err != nil {
			return fmt.Errorf("renewal: swap key into place: %w", err)
		}
		if err := os.Rename(stagingCert, liveCert); err != nil {
			return fmt.Errorf("renewal: swap certificate into place: %w", err)
		}
		return nil

	case certStaged && !keyStaged:
		// The key half of a completed swap already landed live -- this
		// is exactly where a crash between the two renames above leaves
		// things. Finish by swapping the certificate too.
		if err := os.Rename(stagingCert, liveCert); err != nil {
			return fmt.Errorf("renewal: swap certificate into place: %w", err)
		}
		return nil

	default: // keyStaged && !certStaged
		// Only the key half was ever staged: StageAndSwap crashed while
		// staging, before the certificate half existed at all, so the
		// live pair was never touched. Discard the stray half rather
		// than applying it alone, which would pair a brand new key with
		// the still-live old certificate -- exactly the mismatch this
		// whole scheme exists to avoid.
		if err := os.Remove(stagingKey); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("renewal: discard incomplete staged key: %w", err)
		}
		return nil
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
