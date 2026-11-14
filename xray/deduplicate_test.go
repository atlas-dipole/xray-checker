package xray

import (
	"encoding/json"
	"testing"

	"xray-checker/models"
)

func TestDeduplicateProxyConfigs(t *testing.T) {
	base := models.ProxyConfig{Protocol: "vless", Server: "example.com", Port: 443,
		UUID: "00000000-0000-0000-0000-000000000001", Type: "tcp", Security: "tls", Name: "first"}
	for name, change := range map[string]func(*models.ProxyConfig){
		"alias":       func(p *models.ProxyConfig) { p.Name = "SMART | proxy-2"; p.Index = 99; p.StableID = "other" },
		"uuid":        func(p *models.ProxyConfig) { p.UUID = "00000000-0000-0000-0000-000000000002" },
		"sni":         func(p *models.ProxyConfig) { p.SNI = "other.example.com" },
		"security":    func(p *models.ProxyConfig) { p.Security = "reality" },
		"fingerprint": func(p *models.ProxyConfig) { p.Fingerprint = "chrome" },
		"binding":     func(p *models.ProxyConfig) { p.SendThrough = "127.0.0.2" },
		"mask": func(p *models.ProxyConfig) {
			p.RawFinalMask = `{"udp":[{"type":"salamander","settings":{"password":"secret"}}]}`
		},
		"subscription": func(p *models.ProxyConfig) { p.SubName = "other" },
		"group":        func(p *models.ProxyConfig) { p.GroupName = "other" },
		"labels":       func(p *models.ProxyConfig) { p.MetricsLabels = map[string]string{"region": "other"} },
	} {
		t.Run(name, func(t *testing.T) {
			first, second := base, base
			change(&second)
			got := DeduplicateProxyConfigs([]*models.ProxyConfig{&first, &second})
			want := 2
			if name == "alias" || name == "group" {
				want = 1
			}
			if len(got) != want || got[0] != &first {
				t.Fatalf("got %d entries, want %d with first retained", len(got), want)
			}
			for i, p := range got {
				if p.Index != i {
					t.Fatalf("non-contiguous index %d", p.Index)
				}
			}
		})
	}
}

func TestDeduplicateMaskCredentialsAndJSONFormatting(t *testing.T) {
	first := &models.ProxyConfig{Protocol: "trojan", Server: "example.com", Port: 443, Password: "one", RawFinalMask: `{"udp":[{"type":"salamander","settings":{"password":"one"}}]}`}
	alias, differentMask, differentPassword := *first, *first, *first
	alias.RawFinalMask = `{ "udp": [ { "settings": {"password": "one"}, "type": "salamander" } ] }`
	differentMask.RawFinalMask = `{"udp":[{"type":"salamander","settings":{"password":"two"}}]}`
	differentPassword.Password = "two"
	got := DeduplicateProxyConfigs([]*models.ProxyConfig{first, &alias, &differentMask, &differentPassword})
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	data, err := NewConfigGenerator().GenerateConfig(got, 10000, "none")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds  []json.RawMessage
		Outbounds []json.RawMessage
		Routing   struct{ Rules []json.RawMessage }
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 3 || len(config.Outbounds) != 5 {
		t.Fatalf("unexpected generated counts: %d inbounds, %d outbounds", len(config.Inbounds), len(config.Outbounds))
	}
}

func TestDeduplicatePrefersStandaloneNameInEitherOrder(t *testing.T) {
	for _, standaloneFirst := range []bool{false, true} {
		grouped := &models.ProxyConfig{Protocol: "socks", Server: "example.com", Port: 1080,
			Name: "SMART | proxy", GroupName: "SMART", FromMultiNodeProfile: true}
		standalone := *grouped
		standalone.Name = "Germany"
		standalone.GroupName = ""
		standalone.FromMultiNodeProfile = false
		proxies := []*models.ProxyConfig{grouped, &standalone}
		if standaloneFirst {
			proxies[0], proxies[1] = proxies[1], proxies[0]
		}
		got := DeduplicateProxyConfigs(proxies)
		if len(got) != 1 || got[0] != &standalone {
			t.Fatal("standalone name must win regardless of order")
		}
	}
	first := &models.ProxyConfig{Protocol: "socks", Server: "example.com", Port: 1080,
		Name: "proxy", FromMultiNodeProfile: true}
	second := *first
	second.Name = "proxy-2"
	got := DeduplicateProxyConfigs([]*models.ProxyConfig{first, &second})
	if len(got) != 1 || got[0] != first {
		t.Fatal("first alias must remain if no standalone entry exists")
	}
}
