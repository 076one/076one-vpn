package main

import (
	"testing"
)

// v1.8.3: TCP keep-alive sockopt is added to every outbound and still builds in Xray; link values win.
func TestKeepAliveSockopt(t *testing.T) {
	links := []string{
		"ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss",
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp#r",
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=ws&security=tls&path=%2Fws&host=example.com&sni=example.com#ws",
		"trojan://p%40ss@example.com:443?sni=example.com&type=tcp#tr",
	}
	for _, s := range links {
		l, err := ParseLink(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		addKeepAlive(l.Outbound)
		ss := l.Outbound["streamSettings"].(map[string]any)
		so := ss["sockopt"].(map[string]any)
		if so["tcpKeepAliveIdle"] != 20 || so["tcpKeepAliveInterval"] != 10 {
			t.Fatalf("%s: sockopt %v", s, so)
		}
		buildOK(t, l)
	}
	ob := map[string]any{"protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"tcpKeepAliveIdle": 45}}}
	addKeepAlive(ob)
	so := ob["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if so["tcpKeepAliveIdle"] != 45 || so["tcpKeepAliveInterval"] != 10 {
		t.Fatalf("existing sockopt overwritten: %v", so)
	}
}
