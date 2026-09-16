package event

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadBounded(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int
		want    string
		wantErr bool
	}{
		{name: "under the cap", input: "hello", max: 10, want: "hello"},
		{name: "exactly at the cap", input: "hello", max: 5, want: "hello"},
		{name: "one byte over the cap", input: "hello!", max: 5, wantErr: true},
		{name: "empty input", input: "", max: 5, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadBounded(strings.NewReader(tt.input), tt.max)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ReadBounded(%q, %d) succeeded, want error", tt.input, tt.max)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadBounded(%q, %d) returned error: %v", tt.input, tt.max, err)
			}
			if !bytes.Equal(got, []byte(tt.want)) {
				t.Errorf("ReadBounded(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

// TestReadBoundedNeverAllocatesUnbounded proves the point of the function:
// a reader that produces far more than max bytes is cut off at max+1, not
// read to its (in this case unbounded) end.
func TestReadBoundedNeverAllocatesUnbounded(t *testing.T) {
	const max = 1024
	hostile := &infiniteReader{}
	_, err := ReadBounded(hostile, max)
	if err == nil {
		t.Fatal("ReadBounded against an infinite reader succeeded, want error")
	}
	if hostile.produced > max+1 {
		t.Errorf("ReadBounded pulled %d bytes from the reader, want at most %d", hostile.produced, max+1)
	}
}

// infiniteReader never returns io.EOF and tracks how many bytes it has
// been asked to produce, so the test above can prove ReadBounded stopped
// pulling from it at the cap rather than draining it.
type infiniteReader struct {
	produced int
}

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.produced += len(p)
	return len(p), nil
}
