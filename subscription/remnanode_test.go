package subscription

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractConfigDump(t *testing.T) {
	object := `{"outbounds":[],"remarks":"braces { inside } a string"}`
	for _, data := range []string{
		object,
		"◐ Dumping cold XRay configuration...\n✔ Retrieved!\n\n" + object + "\n✔ Dumped!\n",
		"\xef\xbb\xbf\x1b[32m✔ Retrieved!\x1b[0m\r\n" + object + "\r\n\x1b[32m✔ Dumped!\x1b[0m",
		object + "\n✔ Dumped!",
	} {
		got, err := extractConfigDump([]byte(data), true)
		if err != nil || string(got) != object {
			t.Fatalf("extract failed: got %q, err %v", got, err)
		}
	}
	for _, data := range []string{"", "✔ Failed!", "prefix\n{", `{"outbounds":`, `{"inbounds":[]}`, `{"outbounds":null}`} {
		if _, err := extractConfigDump([]byte(data), true); err == nil {
			t.Errorf("expected error for %q", data)
		}
	}
	for _, data := range []string{`[{"outbounds":[]}]`, "vless://test@example.com:443", "dmxlc3M6Ly90ZXN0"} {
		got, err := extractConfigDump([]byte(data), false)
		if err != nil || string(got) != data {
			t.Fatalf("ordinary source changed: got %q, err %v", got, err)
		}
	}
}

func installTestDocker(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("fake Docker requires /bin/sh")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func TestReadRemnanodeConfig(t *testing.T) {
	dir := installTestDocker(t, "printf '%s\\n' \"$@\" > \"$REMNANODE_TEST_ARGS\"\ncat \"$REMNANODE_TEST_OUTPUT\"\n")
	argsPath, outputPath := filepath.Join(dir, "args"), filepath.Join(dir, "output")
	t.Setenv("REMNANODE_TEST_ARGS", argsPath)
	t.Setenv("REMNANODE_TEST_OUTPUT", outputPath)
	for _, object := range []string{`{"outbounds":[],"remarks":"first"}`, `{"outbounds":[],"remarks":"updated"}`} {
		if err := os.WriteFile(outputPath, []byte("✔ Retrieved!\n"+object+"\n✔ Dumped!"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readRemnanodeConfig(context.Background(), "remnanode://my_node-1")
		if err != nil || string(got) != object {
			t.Fatalf("read failed: got %q, err %v", got, err)
		}
		args, err := os.ReadFile(argsPath)
		if err != nil || string(args) != "exec\nmy_node-1\ncli\n--dump-config-raw\n" {
			t.Fatalf("unexpected arguments: %q, err %v", args, err)
		}
	}
}

func TestReadRemnanodeConfigInvalidContainer(t *testing.T) {
	for _, source := range []string{"remnanode://", "remnanode://-option", "remnanode://node/path", "remnanode://node?arg", "remnanode://node;command", "remnanode://node name"} {
		if _, err := readRemnanodeConfig(context.Background(), source); err == nil {
			t.Errorf("accepted invalid source %q", source)
		}
	}
}

func TestReadRemnanodeConfigFailure(t *testing.T) {
	installTestDocker(t, "printf 'secret-stdout'\nprintf 'secret-stderr' >&2\nexit 7\n")
	_, err := readRemnanodeConfig(context.Background(), "remnanode://node")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("expected Docker exit error, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-") {
		t.Fatal("error exposes command output")
	}
}

func TestReadRemnanodeConfigTimeout(t *testing.T) {
	installTestDocker(t, "exec sleep 10\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := readRemnanodeConfig(ctx, "remnanode://node"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestReadRemnanodeConfigMissingDocker(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := readRemnanodeConfig(context.Background(), "remnanode://node"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected missing Docker, got %v", err)
	}
}

func TestReadRemnanodeConfigInvalidOutput(t *testing.T) {
	installTestDocker(t, "printf '✔ Failed to dump config!\\n'\n")
	if _, err := readRemnanodeConfig(context.Background(), "remnanode://node"); err == nil {
		t.Fatal("accepted output without a JSON config")
	}
}

func TestRemnanodeDumpFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/remnanode-dump.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractConfigDump(data, true)
	if err != nil || !bytes.Contains(got, []byte(`"outbounds"`)) {
		t.Fatalf("fixture extraction failed: %v", err)
	}
}
