// Helpers shared by the svpn tunnel, registration and bridge tests. Kept from the removed Worker-mode files
// (wtun.go, vless.go) when Worker mode was deleted in v1.8.2.
package main

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type dnsCacheEnt struct {
	ans []byte
	exp time.Time
}

func dnsQuestion(name string, qtype uint16, id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func errLine(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// clientTLS performs a verified TLS handshake (Chrome or Go fingerprint) over raw with fragmentation.
func clientTLS(ctx context.Context, raw net.Conn, sni string, alpn []string, insecure bool, o dpiOpts) (net.Conn, error) {
	fc := &fragConn{Conn: raw, o: o}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer raw.SetDeadline(time.Time{})
	}
	if o.fp == "go" || o.fp == "" {
		tc := tls.Client(fc, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: insecure})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(o.noDelay)
		}
		return tc, nil
	}
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, err
	}
	var exts []utls.TLSExtension
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = alpn
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue // ALPS is only for h2
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts
	u := utls.UClient(fc, &utls.Config{ServerName: sni, InsecureSkipVerify: insecure, NextProtos: alpn}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(o.noDelay)
	}
	return u, nil
}
