package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFromMultipleSourcesDeduplicatesSMARTGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.json")
	data := `[
	{"remarks":"SMART","outbounds":[
	{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001"}]}]}},
	{"tag":"proxy-2","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000002"}]}]}}]},
	{"remarks":"Standalone","outbounds":[
	{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001"}]}]}}]}
	]`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, sources := range [][]string{{"file://" + path}, {"file://" + path, "file://" + path}} {
		got, err := ReadFromMultipleSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d connections, want 2", len(got))
		}
		if got[0].Name != "Standalone" || got[0].GroupName != "" {
			t.Fatalf("standalone name was not selected: %q (group %q)", got[0].Name, got[0].GroupName)
		}
	}
}
