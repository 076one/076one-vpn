package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func buildOK(t *testing.T, l *Link) {
	t.Helper()
	ob := map[string]any{}
	for k, v := range l.Outbound {
		ob[k] = v
	}
	cfg := map[string]any{"outbounds": []any{ob}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}}
	b, _ := json.Marshal(cfg)
	jc, err := serial.DecodeJSONConfig(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	if _, err := jc.Build(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
}

func TestLinks(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm ws", "add": "example.com", "port": "443", "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/v", "tls": "tls", "sni": "cdn.example.com", "fp": "chrome"})
	ok := map[string]string{
		"vless reality":     "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp#Reality%20DE",
		"vless ws tls":      "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=example.com&sni=example.com#ws",
		"vless grpc":        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=grpc&serviceName=gun&mode=multi&security=tls&sni=example.com#grpc",
		"vless plain":       "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:10086?type=tcp&security=none#plain",
		"vless http hdr":    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:80?type=tcp&headerType=http&host=a.com&path=%2F#h",
		"vless xhttp":       "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=xhttp&path=%2Fx&mode=auto&security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sni=a.com#x",
		"vless httpupgrade": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:80?type=httpupgrade&path=%2Fu&host=a.com#u",
		"vmess":             "vmess://" + base64.StdEncoding.EncodeToString(vm),
		"trojan":            "trojan://p%40ss@example.com:443?sni=example.com&type=tcp#tr",
		"trojan ws":         "trojan://secret@example.com:443?security=tls&type=ws&path=%2Ft#trws",
		"ss sip002":         "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw123")) + "@1.2.3.4:8388#ss1",
		"ss legacy":         "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw:x@1.2.3.4:8388")) + "#ss2",
		"ss 2022":           "ss://2022-blake3-aes-128-gcm:" + "YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D" + "@1.2.3.4:8388#ss3",
	}
	for name, s := range ok {
		l, err := ParseLink(s)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		buildOK(t, l)
	}
	l, _ := ParseLink(ok["vless reality"])
	if l.Name != "Reality DE" || l.Port != 443 {
		t.Errorf("name/port: %q %d", l.Name, l.Port)
	}
	bad := []string{"http://x", "vless://@a:1", "vless://id@a:99999", "vless://id@a:443?type=h2", "ss://abc", "vless://id@a:443?security=reality"}
	for _, s := range bad {
		if _, err := ParseLink(s); err == nil {
			t.Errorf("expected error: %s", s)
		}
	}
}

func TestSubscription(t *testing.T) {
	list := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=none#a\ntrojan://x@b.com:443#b\nhello\n"
	got := ParseSubscription([]byte(base64.StdEncoding.EncodeToString([]byte(list))))
	if len(got) != 2 {
		t.Fatalf("base64 sub: %v", got)
	}
	got = ParseSubscription([]byte(list))
	if len(got) != 2 {
		t.Fatalf("plain sub: %v", got)
	}
}
