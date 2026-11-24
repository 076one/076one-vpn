// Share-link parsing for 076one "Config + Psiphon" mode: vless:// (tcp/raw, ws, grpc, httpupgrade, xhttp; tls or
// reality), vmess:// (v2rayN base64 JSON), trojan://, ss:// (SIP002 and the legacy base64 form). Each link becomes one
// Xray-core outbound (JSON, built and validated by Xray's own infra/conf).
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Link is a parsed proxy link.
type Link struct {
	Scheme   string
	Name     string
	Host     string
	Port     int
	Outbound map[string]any
	Warn     []string // non-fatal notes (e.g. allowInsecure no longer supported by Xray)
}

var supportedSchemes = []string{"vless://", "vmess://", "trojan://", "ss://"}

func isLink(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, p := range supportedSchemes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	// padding mistakes: strip '=' and try raw
	t := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(t); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("bad base64")
}

// ParseLink parses one share link.
func ParseLink(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	low := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(low, "vmess://"):
		return parseVmess(raw[8:])
	case strings.HasPrefix(low, "vless://"):
		return parseURLLink(raw, "vless")
	case strings.HasPrefix(low, "trojan://"):
		return parseURLLink(raw, "trojan")
	case strings.HasPrefix(low, "ss://"):
		return parseSS(raw)
	}
	return nil, errors.New("unsupported link (vless, vmess, trojan, ss only)")
}

func splitHostPort(hp string) (string, int, error) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, fmt.Errorf("bad host:port %q", hp)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, fmt.Errorf("bad port %q", p)
	}
	if h == "" {
		return "", 0, errors.New("empty host")
	}
	return h, n, nil
}

type params map[string]string

func (p params) get(keys ...string) string {
	for _, k := range keys {
		if v, ok := p[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func csv(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// streamSettings builds Xray streamSettings from link query parameters (shared by vless/trojan/vmess).
func streamSettings(p params, host string, l *Link) (map[string]any, error) {
	network := strings.ToLower(p.get("type", "net"))
	if network == "" {
		network = "tcp"
	}
	ss := map[string]any{}
	hostHdr := p.get("host")
	path := p.get("path")
	switch network {
	case "tcp", "raw":
		ss["network"] = "raw"
		if strings.EqualFold(p.get("headerType"), "http") {
			req := map[string]any{"path": []string{orDefault(path, "/")}}
			if hostHdr != "" {
				req["headers"] = map[string]any{"Host": csv(hostHdr)}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws", "websocket":
		ss["network"] = "ws"
		ws := map[string]any{"path": orDefault(path, "/")}
		if hostHdr != "" {
			ws["host"] = hostHdr
		}
		ss["wsSettings"] = ws
	case "httpupgrade":
		ss["network"] = "httpupgrade"
		hu := map[string]any{"path": orDefault(path, "/")}
		if hostHdr != "" {
			hu["host"] = hostHdr
		}
		ss["httpupgradeSettings"] = hu
	case "grpc", "gun":
		ss["network"] = "grpc"
		g := map[string]any{"serviceName": p.get("serviceName", "path")}
		if strings.EqualFold(p.get("mode"), "multi") {
			g["multiMode"] = true
		}
		if a := p.get("authority"); a != "" {
			g["authority"] = a
		}
		ss["grpcSettings"] = g
	case "xhttp", "splithttp":
		ss["network"] = "xhttp"
		x := map[string]any{"path": orDefault(path, "/")}
		if hostHdr != "" {
			x["host"] = hostHdr
		}
		if m := p.get("mode"); m != "" {
			x["mode"] = m
		}
		if extra := p.get("extra"); extra != "" {
			var e any
			if json.Unmarshal([]byte(extra), &e) == nil {
				x["extra"] = e
			}
		}
		ss["xhttpSettings"] = x
	case "kcp", "mkcp":
		ss["network"] = "kcp"
	default:
		return nil, fmt.Errorf("transport %q is not supported by Xray-core any more", network)
	}

	sec := strings.ToLower(p.get("security"))
	if sec == "" && l.Scheme == "trojan" {
		sec = "tls" // trojan defaults to TLS
	}
	sni := p.get("sni", "peer", "serverName")
	fp := p.get("fp", "fingerprint")
	if sec == "" || sec == "none" {
		ss["security"] = "none"
		return ss, nil
	}
	switch sec {
	case "tls", "xtls":
		ss["security"] = "tls"
		t := map[string]any{}
		if sni == "" {
			if hostHdr != "" && net.ParseIP(hostHdr) == nil {
				sni = strings.Split(hostHdr, ",")[0]
			} else if net.ParseIP(host) == nil {
				sni = host
			}
		}
		if sni != "" {
			t["serverName"] = sni
		}
		t["fingerprint"] = orDefault(fp, "chrome")
		if a := csv(p.get("alpn")); len(a) > 0 {
			t["alpn"] = a
		}
		if pcs := p.get("pcs", "pinnedPeerCertSha256"); pcs != "" {
			t["pinnedPeerCertSha256"] = pcs
		}
		if vcn := p.get("vcn", "verifyPeerCertByName"); vcn != "" {
			t["verifyPeerCertByName"] = vcn
		}
		if ech := p.get("ech"); ech != "" {
			t["echConfigList"] = ech
		}
		if v := p.get("allowInsecure", "insecure", "allow_insecure"); v == "1" || strings.EqualFold(v, "true") {
			l.Warn = append(l.Warn, "allowInsecure ignored (removed from Xray-core); the server certificate is verified")
		}
		ss["tlsSettings"] = t
	case "reality":
		ss["security"] = "reality"
		pbk := p.get("pbk", "publicKey")
		if pbk == "" {
			return nil, errors.New("reality link without pbk (public key)")
		}
		r := map[string]any{"publicKey": pbk, "fingerprint": orDefault(fp, "chrome")}
		if sni != "" {
			r["serverName"] = sni
		}
		if sid := p.get("sid", "shortId"); sid != "" {
			r["shortId"] = sid
		}
		if spx := p.get("spx", "spiderX"); spx != "" {
			r["spiderX"] = spx
		}
		if pqv := p.get("pqv", "mldsa65Verify"); pqv != "" {
			r["mldsa65Verify"] = pqv
		}
		ss["realitySettings"] = r
	default:
		return nil, fmt.Errorf("security %q not supported", sec)
	}
	return ss, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func fragmentName(u *url.URL) string {
	if u.Fragment != "" {
		return u.Fragment
	}
	return ""
}

func parseURLLink(raw, scheme string) (*Link, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad %s link: %v", scheme, err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("%s link without id/password", scheme)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	p := params{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			p[k] = v[0]
		}
	}
	l := &Link{Scheme: scheme, Name: fragmentName(u), Host: host, Port: port}
	ss, err := streamSettings(p, host, l)
	if err != nil {
		return nil, err
	}
	secret := u.User.Username()
	if pw, ok := u.User.Password(); ok && scheme == "trojan" {
		secret = secret + ":" + pw // trojan passwords may contain ':'
	}
	switch scheme {
	case "vless":
		user := map[string]any{"id": secret, "encryption": orDefault(p.get("encryption"), "none")}
		if f := p.get("flow"); f != "" {
			user["flow"] = f
		}
		l.Outbound = map[string]any{
			"protocol":       "vless",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": host, "port": port, "users": []any{user}}}},
			"streamSettings": ss,
		}
	case "trojan":
		l.Outbound = map[string]any{
			"protocol":       "trojan",
			"settings":       map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "password": secret}}},
			"streamSettings": ss,
		}
	}
	return l, nil
}

func parseVmess(body string) (*Link, error) {
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	b, err := b64decode(body)
	if err != nil {
		return nil, errors.New("vmess link is not base64 JSON")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errors.New("vmess link is not valid JSON")
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	port, _ := strconv.Atoi(str("port"))
	host := str("add")
	if host == "" || port <= 0 || port > 65535 {
		return nil, errors.New("vmess link without address/port")
	}
	id := str("id")
	if id == "" {
		return nil, errors.New("vmess link without id")
	}
	p := params{"type": str("net"), "headerType": str("type"), "host": str("host"), "path": str("path"),
		"security": str("tls"), "sni": str("sni"), "alpn": str("alpn"), "fp": str("fp"), "serviceName": str("path")}
	if p["type"] == "grpc" {
		p["mode"] = str("type")
		p["headerType"] = ""
	}
	if p["security"] == "" {
		p["security"] = "none"
	}
	l := &Link{Scheme: "vmess", Name: str("ps"), Host: host, Port: port}
	ss, err := streamSettings(p, host, l)
	if err != nil {
		return nil, err
	}
	aid, _ := strconv.Atoi(str("aid"))
	if aid != 0 {
		l.Warn = append(l.Warn, "alterId>0 (legacy VMess MD5) is not supported by Xray-core; using AEAD")
	}
	l.Outbound = map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": port,
			"users": []any{map[string]any{"id": id, "security": orDefault(str("scy"), "auto")}}}}},
		"streamSettings": ss,
	}
	return l, nil
}

func parseSS(raw string) (*Link, error) {
	body := raw[5:]
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		query = body[i+1:]
		body = body[:i]
	}
	body = strings.TrimSuffix(body, "/")
	var method, password, hostport string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		// SIP002: userinfo is base64(method:password) or percent-encoded method:password (2022 ciphers)
		ui := body[:at]
		hostport = body[at+1:]
		if dec, err := b64decode(ui); err == nil && strings.Contains(string(dec), ":") {
			ui = string(dec)
		} else if un, err := url.PathUnescape(ui); err == nil {
			ui = un
		}
		k := strings.IndexByte(ui, ':')
		if k < 0 {
			return nil, errors.New("ss link: no method:password")
		}
		method, password = ui[:k], ui[k+1:]
	} else {
		dec, err := b64decode(body)
		if err != nil {
			return nil, errors.New("ss link is not valid")
		}
		s := string(dec)
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			return nil, errors.New("ss link is not valid")
		}
		hostport = s[at+1:]
		k := strings.IndexByte(s[:at], ':')
		if k < 0 {
			return nil, errors.New("ss link: no method:password")
		}
		method, password = s[:k], s[k+1:at]
	}
	if q, err := url.ParseQuery(query); err == nil && q.Get("plugin") != "" {
		return nil, errors.New("ss plugins (obfs/v2ray-plugin) are not supported")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	l := &Link{Scheme: "ss", Name: name, Host: host, Port: port}
	l.Outbound = map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port,
			"method": strings.ToLower(method), "password": password}}},
	}
	return l, nil
}

// ParseSubscription turns a subscription body (base64 list or plain text) into share links.
func ParseSubscription(body []byte) []string {
	text := string(body)
	if !containsLink(text) {
		if dec, err := b64decode(text); err == nil {
			text = string(dec)
		}
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if isLink(line) {
			out = append(out, line)
		} else if strings.Contains(line, "://") == false && len(line) > 16 {
			// some panels base64 each line
			if dec, err := b64decode(line); err == nil && isLink(string(dec)) {
				out = append(out, strings.TrimSpace(string(dec)))
			}
		}
	}
	return out
}

func containsLink(s string) bool {
	for _, p := range supportedSchemes {
		if strings.Contains(strings.ToLower(s), p) {
			return true
		}
	}
	return false
}
