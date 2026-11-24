// v1.6: aetherid converts our existing WARP identity (config.json: private_key SEC1 base64, id, access_token,
// ipv4, ipv6) into an Aether identity TOML, so the Aether core reuses the already-registered WARP device with no
// call to the WARP API. Ported from aether-prep/usque2aether. The MASQUE client cert is self-signed from the same
// enrolled EC key, exactly as Aether (and usque) do it.
//
//	aetherid -in config.json -out masque.toml   -> "OK path" | "ERR …"
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// Cloudflare WARP's public WireGuard peer key (only used if this identity is ever run with --wg).
const cfWGPeerKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

func tomlQ(s string) string {
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + "\""
}

// aetherIdentity returns the Aether masque TOML for a usque/o76core config.json.
func aetherIdentity(cfgJSON []byte, now time.Time) ([]byte, error) {
	var u struct {
		PrivateKey  string `json:"private_key"`
		ID          string `json:"id"`
		AccessToken string `json:"access_token"`
		IPv4        string `json:"ipv4"`
		IPv6        string `json:"ipv6"`
	}
	if err := json.Unmarshal(cfgJSON, &u); err != nil {
		return nil, err
	}
	if u.PrivateKey == "" || u.ID == "" || u.AccessToken == "" {
		return nil, errors.New("config.json has no registered WARP identity (private_key/id/access_token)")
	}
	der, err := base64.StdEncoding.DecodeString(u.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %v", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("private_key: %v", err)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0), Subject: pkix.Name{CommonName: "aether"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0)}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	wg := make([]byte, 32) // placeholder of valid length, never enrolled; MASQUE does not use it
	_, _ = rand.Read(wg)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8})
	return []byte(fmt.Sprintf("device_id = %s\naccess_token = %s\ncert_pem = \"\"\"\n%s\"\"\"\nkey_pem = \"\"\"\n%s\"\"\"\ncert_issued_at = %d\nipv4 = %s\nipv6 = %s\nwg_private_key = %s\nwg_peer_public_key = %s\nclient_id = \"\"\norganization = \"\"\ngateway_proxy = \"\"\nassigned_endpoint = \"\"\n",
		tomlQ(u.ID), tomlQ(u.AccessToken), certPEM, keyPEM, now.Unix(), tomlQ(u.IPv4), tomlQ(u.IPv6),
		tomlQ(base64.StdEncoding.EncodeToString(wg)), tomlQ(cfWGPeerKey))), nil
}

func cmdAetherID(args []string) {
	fs := flag.NewFlagSet("aetherid", flag.ExitOnError)
	in := fs.String("in", "config.json", "o76core/usque config.json")
	out_ := fs.String("out", "masque.toml", "Aether identity TOML to write")
	fs.StringVar(in, "c", "config.json", "alias of -in")
	fs.StringVar(out_, "o", "masque.toml", "alias of -out")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*in)
	if err != nil {
		fail("%v", err)
	}
	t, err := aetherIdentity(b, time.Now())
	if err != nil {
		fail("%v", err)
	}
	tmp := *out_ + ".tmp"
	if err := os.WriteFile(tmp, t, 0600); err != nil {
		fail("%v", err)
	}
	if err := os.Rename(tmp, *out_); err != nil {
		fail("%v", err)
	}
	out("OK %s", *out_)
}
