package xray

import (
	"testing"

	"xray-checker/models"
)

func trojan(server string, labels map[string]string) *models.ProxyConfig {
	return &models.ProxyConfig{
		Protocol:      "trojan",
		Server:        server,
		Port:          443,
		Name:          "n",
		Password:      "pw",
		MetricsLabels: labels,
	}
}

func TestIsConfigsEqual_DetectsMetricsLabelChange(t *testing.T) {
	old := []*models.ProxyConfig{trojan("1.1.1.1", map[string]string{"location": "NL"})}

	// Same connection, same labels -> equal.
	same := []*models.ProxyConfig{trojan("1.1.1.1", map[string]string{"location": "NL"})}
	if !IsConfigsEqual(old, same) {
		t.Errorf("identical configs should be equal")
	}

	// Same connection, changed label value -> not equal (must trigger refresh).
	changedVal := []*models.ProxyConfig{trojan("1.1.1.1", map[string]string{"location": "DE"})}
	if IsConfigsEqual(old, changedVal) {
		t.Errorf("a changed metrics label value must be detected as a change")
	}

	// Same connection, added label key -> not equal.
	addedKey := []*models.ProxyConfig{trojan("1.1.1.1", map[string]string{"location": "NL", "hoster": "X"})}
	if IsConfigsEqual(old, addedKey) {
		t.Errorf("an added metrics label key must be detected as a change")
	}

	// Removed all labels -> not equal.
	noLabels := []*models.ProxyConfig{trojan("1.1.1.1", nil)}
	if IsConfigsEqual(old, noLabels) {
		t.Errorf("removing metrics labels must be detected as a change")
	}

	// Different connection -> not equal (baseline behavior preserved).
	diffConn := []*models.ProxyConfig{trojan("9.9.9.9", map[string]string{"location": "NL"})}
	if IsConfigsEqual(old, diffConn) {
		t.Errorf("different server must be detected as a change")
	}
}

func TestIsConfigsEqual_DetectsSendThroughChange(t *testing.T) {
	for _, labels := range []map[string]string{nil, {"location": "NL"}} {
		old := trojan("1.1.1.1", labels)
		for _, source := range []string{"", "192.0.2.1", "2001:db8::1"} {
			updated := trojan("1.1.1.1", labels)
			updated.SendThrough = source
			if old.GenerateStableID() != updated.GenerateStableID() {
				t.Fatal("sendThrough must not change public stable ID")
			}
			if IsConfigsEqual([]*models.ProxyConfig{old}, []*models.ProxyConfig{updated}) != (source == "") {
				t.Fatalf("incorrect config comparison for sendThrough %q", source)
			}
			if !IsConfigsEqual([]*models.ProxyConfig{updated}, []*models.ProxyConfig{updated}) {
				t.Fatalf("identical source bindings must compare equal: %q", source)
			}
		}
	}
}
