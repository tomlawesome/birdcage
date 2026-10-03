package event

import (
	"fmt"
	"io"
)

// ReadBounded reads r until EOF or until it has produced more than max
// bytes, whichever comes first, and never buffers more than max+1 bytes
// doing it. This is the "reject oversize input without allocating it all"
// bound issue #48 requires of both the log tailer and the loopback
// listener: a hostile or malfunctioning sender that never stops writing
// must not be able to force an unbounded read, and a sender that merely
// exceeds the cap must not cost a full-size allocation just to be
// rejected.
//
// Callers pass MaxLogLineBytes or MaxWebhookBodyBytes as max, matching the
// road they are reading.
func ReadBounded(r io.Reader, max int) ([]byte, error) {
	// io.LimitReader stops the underlying read at max+1 bytes rather than
	// max, so an input that is exactly at the cap is distinguished from
	// one that exceeds it -- reading only max bytes would silently accept
	// a truncated prefix of an oversize input as if it were the whole
	// thing.
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("input exceeds the %d-byte cap", max)
	}
	return data, nil
}
