package auth

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/logging"
)

// Issue #164 (note 63923): gauntlet's escape code reaches the log whatever
// BIRDCAGE_LOG_LEVEL says, in words docs/configuration.md promises
// (`with escape code`), like the setup and unlock codes.
func TestEscapeCodeIsPrintedWhateverTheLogLevelAndMatchesTheDocs(t *testing.T) {
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	if !strings.Contains(string(docs), "with escape code") {
		t.Fatal("docs/configuration.md does not mention the `with escape code` line")
	}
	line := regexp.MustCompile(`with escape code (\S+)`)
	for _, level := range []string{"info", "error"} {
		t.Run(level, func(t *testing.T) {
			logging.SetLevel(level)
			t.Cleanup(func() { logging.SetLevel("info") })
			f, err := os.CreateTemp(t.TempDir(), "stdout")
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			old := os.Stdout
			os.Stdout = f
			escapeCode(logging.New("auth"))("erebus-admin", "192.0.2.10", "fake-escape-code-1")
			os.Stdout = old
			_ = f.Close()
			out, _ := os.ReadFile(f.Name())
			m := line.FindStringSubmatch(string(out))
			if m == nil || m[1] != "fake-escape-code-1" {
				t.Errorf("stdout at level %s = %q, want one `with escape code fake-escape-code-1` line", level, out)
			}
			if got := len(line.FindAllString(string(out), -1)); got != 1 {
				t.Errorf("escape code lines = %d, want exactly 1", got)
			}
		})
	}
}
