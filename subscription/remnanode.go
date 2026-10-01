package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var (
	containerIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	ansiEscape          = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")
	jsonObjectLine      = regexp.MustCompile(`(?m)^[\t ]*\{`)
)

func readRemnanodeConfig(ctx context.Context, source string) ([]byte, error) {
	container := strings.TrimPrefix(source, "remnanode://")
	if !containerIdentifier.MatchString(container) {
		return nil, fmt.Errorf("remnanode source requires a valid container name or ID")
	}

	data, err := exec.CommandContext(ctx, "docker", "exec", container, "cli", "--dump-config-raw").Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("remnanode config command canceled: %w", ctx.Err())
	}
	if err != nil {
		// Do not include stdout/stderr: CLI output can contain credentials.
		return nil, fmt.Errorf("failed to retrieve remnanode config: %w", err)
	}
	return extractConfigDump(data, true)
}

// extractConfigDump removes the CLI's progress messages around a JSON object.
// Non-dump files still use the existing JSON-array/share-link parser.
func extractConfigDump(data []byte, required bool) ([]byte, error) {
	cleaned := bytes.TrimSpace(ansiEscape.ReplaceAll(data, nil))
	cleaned = bytes.TrimSpace(bytes.TrimPrefix(cleaned, []byte("\xef\xbb\xbf")))
	if !required && bytes.HasPrefix(cleaned, []byte("[")) {
		return cleaned, nil
	}
	start := jsonObjectLine.FindIndex(cleaned)
	if start == nil {
		if required {
			return nil, fmt.Errorf("remnanode dump contains no JSON config object")
		}
		return cleaned, nil
	}

	var object json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(cleaned[start[0]:])).Decode(&object); err != nil {
		return nil, fmt.Errorf("invalid JSON config dump")
	}
	var config struct {
		Outbounds json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(object, &config); err != nil || len(config.Outbounds) == 0 || bytes.Equal(config.Outbounds, []byte("null")) {
		return nil, fmt.Errorf("JSON config dump contains no outbounds")
	}
	return object, nil
}
