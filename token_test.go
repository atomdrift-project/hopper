package hopper

import (
	"os"
	"path/filepath"
	"testing"
)

const testToken = "1234567890abcdef1234567890abcdef"

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"plain":   testToken,
		"newline": testToken + "\n",
		"leading": "\n\n  " + testToken + "  \nignored\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ReadTokenFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != testToken {
			t.Errorf("%s: got %q", name, got)
		}
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(empty); err == nil {
		t.Error("empty file accepted")
	}
	if _, err := ReadTokenFile(filepath.Join(dir, "absent")); err == nil {
		t.Error("missing file accepted")
	}
}

// A missing, empty, or too-short token file must be an error, never a nil
// digest — that would silently serve an open API.
func TestResolveAPIToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hopper")
	if err := os.WriteFile(path, []byte("  "+testToken+"  \nignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		env, path, want string
	}{
		"env wins over file":    {env: "from-env", path: path, want: "from-env"},
		"blank env falls back":  {env: "   ", path: path, want: testToken},
		"file is trimmed":       {env: "", path: path, want: testToken},
		"env is trimmed":        {env: " padded ", path: "", want: "padded"},
		"no env and no file":    {env: "", path: "", want: ""},
		"missing file is empty": {env: "", path: filepath.Join(dir, "absent"), want: ""},
	} {
		if got := resolveAPIToken(tc.env, tc.path); got != tc.want {
			t.Errorf("%s: resolveAPIToken(%q, %q) = %q, want %q", name, tc.env, tc.path, got, tc.want)
		}
	}
}
