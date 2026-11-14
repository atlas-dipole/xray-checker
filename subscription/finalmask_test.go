package subscription

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"xray-checker/xray"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const completeFinalMask = `{
	"tcp":[
		{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"1-3","lengths":["50-80",100],"delays":[1,"2-3"],"maxSplit":4}},
		{"type":"filter","settings":{"blockedSourceIPs":["192.0.2.0/24"]}}
	],
	"udp":[
		{"type":"noise","settings":{"reset":"10-20","noise":[{"rand":"20-30","delay":"1-2"}]}},
		{"type":"salamander","settings":{"password":"mask-secret","packetSize":"100-200"}},
		{"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","interval":"10-30","remotePorts":"20000-30000","remoteIPs":["192.0.2.1"]}}
	],
	"quicParams":{"congestion":"bbr","bbrProfile":"conservative","brutalUp":"50 mbps","brutalDown":"100 mbps",
		"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":9007199254740993,"initConnectionReceiveWindow":262144,
		"maxConnectionReceiveWindow":524288,"maxIdleTimeout":45,"keepAlivePeriod":10,"disablePathMTUDiscovery":true,
		"disableChromeParrot":true,"disableGSO":true,"maxIncomingStreams":32,"disableStatelessReset":true}
}`

func TestFinalMaskSurvivesSubscriptionAndCoreBuild(t *testing.T) {
	var want interface{}
	decoder := json.NewDecoder(strings.NewReader(completeFinalMask))
	decoder.UseNumber()
	if err := decoder.Decode(&want); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"json", "json-array", "sockopt", "share-link"} {
		t.Run(source, func(t *testing.T) {
			stream := `"network":"tcp","security":"tls","tlsSettings":{"fingerprint":"chrome","serverName":"example.com"},"finalmask":` + completeFinalMask
			if source == "sockopt" {
				stream = `"network":"tcp","security":"tls","tlsSettings":{"fingerprint":"chrome"},"sockopt":{"finalMask":` + completeFinalMask + `}`
			}
			input := `{"outbounds":[{"tag":"masked","protocol":"vless","settings":{"address":"example.com","port":443,"id":"00000000-0000-0000-0000-000000000000","encryption":"none"},"streamSettings":{` + stream + `}}]}`
			if source == "json-array" {
				input = "[" + input + "]"
			}
			if source == "share-link" {
				input = "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&type=tcp&security=tls&fp=chrome&sni=example.com&fm=" + url.QueryEscape(completeFinalMask) + "#masked"
			}
			parsed, err := NewParser().Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Configs) != 1 {
				t.Fatalf("expected one proxy, got %d", len(parsed.Configs))
			}
			generator := xray.NewConfigGenerator()
			outbound := generator.GenerateProxyOutbound(parsed.Configs[0])
			generatedStream := outbound["streamSettings"].(map[string]interface{})
			if !reflect.DeepEqual(generatedStream["finalmask"], want) {
				t.Fatalf("finalmask changed in round trip: got %v, want %v", generatedStream["finalmask"], want)
			}
			if _, exists := generatedStream["sockopt"]; exists {
				t.Fatal("mask must be emitted at streamSettings level")
			}
			data, err := generator.GenerateConfig(parsed.Configs, 20000, "none")
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			built, err := decoded.Build()
			if err != nil {
				t.Fatal(err)
			}
			message, err := built.Outbound[2].SenderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			streamSettings := message.(*proxyman.SenderConfig).StreamSettings
			if len(streamSettings.Tcpmasks) != 2 || len(streamSettings.Udpmasks) != 3 || streamSettings.QuicParams.GetCongestion() != "bbr" {
				t.Fatalf("Xray lost mask chain or QUIC parameters: %v", streamSettings)
			}
			if streamSettings.QuicParams.GetMaxStreamReceiveWindow() != 9007199254740993 {
				t.Fatal("QUIC window size lost integer precision")
			}
		})
	}
}

func TestInvalidFinalMaskRejectsOnlyItsProxy(t *testing.T) {
	input := `{"outbounds":[{"tag":"good","protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000"}},` +
		`{"tag":"bad","protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"00000000-0000-0000-0000-000000000000"},"streamSettings":{"finalmask":{"tcp":[{"type":"nonexistent-mask"}]}}}]}`
	parsed, err := NewParser().Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	survivors, err := xray.NewConfigGenerator().GenerateValidatedConfig(parsed.Configs, 20000, filepath.Join(t.TempDir(), "config.json"), "none")
	if err != nil || len(survivors) != 1 || survivors[0].Name != "good" {
		t.Fatalf("invalid mask must exclude only the bad proxy: got %v, err %v", survivors, err)
	}
}

func TestHysteriaShareLinkPreservesFinalMask(t *testing.T) {
	parsed, err := NewParser().Parse("hy2://auth@example.com:443?mport=20000-30000&hop-interval=15&obfs=salamander&obfs-password=mask-secret&up=50%20mbps&down=100%20mbps#hy2")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Configs) != 1 {
		t.Fatalf("expected one Hysteria proxy, got %d", len(parsed.Configs))
	}
	outbound := xray.NewConfigGenerator().GenerateProxyOutbound(parsed.Configs[0])
	mask := outbound["streamSettings"].(map[string]interface{})["finalmask"].(map[string]interface{})
	udp := mask["udp"].([]interface{})
	if len(udp) != 2 || udp[0].(map[string]interface{})["type"] != "salamander" || udp[1].(map[string]interface{})["type"] != "udphop" {
		t.Fatalf("Hysteria mask chain lost: %v", mask)
	}
	if mask["quicParams"].(map[string]interface{})["brutalUp"] != "50 mbps" {
		t.Fatal("QUIC congestion settings lost")
	}
	survivors, err := xray.NewConfigGenerator().GenerateValidatedConfig(parsed.Configs, 20000, filepath.Join(t.TempDir(), "config.json"), "none")
	if err != nil || len(survivors) != 1 {
		t.Fatalf("Hysteria mask config rejected: %v", err)
	}
}
