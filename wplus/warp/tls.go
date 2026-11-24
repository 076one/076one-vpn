package warp

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/bepass-org/warp-plus/iputils"

	"github.com/noql-net/certpool"
	tls "github.com/refraction-networking/utls"
	xproxy "golang.org/x/net/proxy"
)

// Dialer is a struct that holds various options for custom dialing.
type Dialer struct {
	l *slog.Logger
}

const utlsExtensionSNICurve uint16 = 0x15

// SNICurveExtension implements SNICurve (0x15) extension
type SNICurveExtension struct {
	*tls.GenericExtension
	SNICurveLen int
	WillPad     bool // set false to disable extension
}

// Len returns the length of the SNICurveExtension.
func (e *SNICurveExtension) Len() int {
	if e.WillPad {
		return 4 + e.SNICurveLen
	}
	return 0
}

// Read reads the SNICurveExtension.
func (e *SNICurveExtension) Read(b []byte) (n int, err error) {
	if !e.WillPad {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(utlsExtensionSNICurve >> 8)
	b[1] = byte(utlsExtensionSNICurve)
	b[2] = byte(e.SNICurveLen >> 8)
	b[3] = byte(e.SNICurveLen)
	y := make([]byte, 1200)
	copy(b[4:], y)
	return e.Len(), io.EOF
}

const SNICurveSize = 1200

func spec(sni string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS12,
		TLSVersMin: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256, // tls 1.3
			tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&SNICurveExtension{
				SNICurveLen: SNICurveSize,
				WillPad:     true,
			},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
					tls.ECDSAWithSHA1,
					tls.PKCS1WithSHA1,
				},
			},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // pskModeDHE
			&tls.SNIExtension{ServerName: sni},
		},
		GetSessionID: nil,
	}
}

func makeTLSHelloPacketWithSNICurve(plainConn net.Conn, config *tls.Config, sni string) (*tls.UConn, error) {
	utlsConn := tls.UClient(plainConn, config, tls.HelloCustom)
	err := utlsConn.ApplyPreset(spec(sni))
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %w", err)
	}

	err = utlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %w", err)
	}

	return utlsConn, nil
}

func dialCurve(network string, ip netip.Addr, sni string) (net.Conn, error) {
	plainDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	plainConn, err := rawDial(plainDialer, network, netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		return nil, err
	}

	config := tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		RootCAs:    certpool.Roots(),
	}

	tlsConn, handshakeErr := makeTLSHelloPacketWithSNICurve(plainConn, &config, sni)
	if handshakeErr != nil {
		_ = plainConn.Close()
		return nil, handshakeErr
	}
	return tlsConn, nil
}

func dial2(network string, ip netip.Addr, sni string) (net.Conn, error) {
	plainDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	plainConn, err := rawDial(plainDialer, network, netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		RootCAs:    certpool.Roots(),
	}

	tlsConn := tls.Client(plainConn, &tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		_ = plainConn.Close()
		return nil, err
	}

	return tlsConn, nil
}
func dial3(network string, ip netip.Addr, sni string) (net.Conn, error) {
	plainDialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	plainConn, err := rawDial(plainDialer, network, netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		RootCAs:    certpool.Roots(),
	}

	tlsConn := tls.UClient(plainConn, &tlsConfig, tls.HelloChrome_Auto)
	err = tlsConn.Handshake()
	if err != nil {
		_ = plainConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// TLSDial dials a TLS connection.
func (d *Dialer) TLSDial(network, addr string) (net.Conn, error) {
	sni, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := iputils.RandomIPFromPrefix(netip.MustParsePrefix("141.101.113.0/24"))
	if err != nil {
		return nil, err
	}

	var tlsConn net.Conn

	d.l.Info("attempting TLS dial fprint 1")
	err = retry.Do(
		func() error {
			tlsConn, err = dialCurve(network, ip, sni)
			return err
		},
		retry.Attempts(3),
		retry.Delay(250*time.Millisecond),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			d.l.Info("retrying TLS dial", "attempt", n, "error", err)
		}),
	)

	if err != nil {
		d.l.Info("attempting TLS dial fprint 2")
		err = retry.Do(
			func() error {
				tlsConn, err = dial2(network, ip, sni)
				return err
			},
			retry.Attempts(3),
			retry.Delay(250*time.Millisecond),
			retry.DelayType(retry.FixedDelay),
			retry.OnRetry(func(n uint, err error) {
				d.l.Info("retrying TLS dial", "attempt", n, "error", err)
			}),
		)
	}

	if err != nil {
		d.l.Info("attempting TLS dial fprint 3")
		err = retry.Do(
			func() error {
				tlsConn, err = dial3(network, ip, sni)
				return err
			},
			retry.Attempts(3),
			retry.Delay(250*time.Millisecond),
			retry.DelayType(retry.FixedDelay),
			retry.OnRetry(func(n uint, err error) {
				d.l.Info("retrying TLS dial", "attempt", n, "error", err)
			}),
		)
	}

	// 076one patch: upstream returned (nil, nil) when all three fingerprints failed.
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// 076one patch: when WP_REG_PROXY is set (socks5://[user:pass@]host:port, http://[user:pass@]host:port or bare
// host:port = SOCKS5), the WARP API (registration only) is reached through that bridge instead of directly, because
// direct registration is blocked on some Iranian networks. The WireGuard tunnel itself never uses it.
func rawDial(d *net.Dialer, network, addr string) (net.Conn, error) {
	list := os.Getenv("WP_REG_PROXY")
	if list == "" {
		return d.Dial(network, addr)
	}
	// 076one: comma-separated bridges, tried in order, then direct as the last resort.
	var errs []string
	for _, pa := range strings.Split(list, ",") {
		pa = strings.TrimSpace(pa)
		if pa == "" {
			continue
		}
		c, err := dialVia(d, pa, addr)
		if err == nil && c != nil {
			return c, nil
		}
		if err == nil {
			err = fmt.Errorf("nil conn")
		}
		errs = append(errs, err.Error())
	}
	c, err := d.Dial(network, addr)
	if err != nil {
		errs = append(errs, "direct: "+err.Error())
		return nil, fmt.Errorf("registration dial failed: %s", strings.Join(errs, "; "))
	}
	return c, nil
}

func dialVia(d *net.Dialer, pa, addr string) (net.Conn, error) {
	if !strings.Contains(pa, "://") {
		pa = "socks5://" + pa
	}
	u, err := url.Parse(pa)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		pd, err := xproxy.SOCKS5("tcp", u.Host, auth, d)
		if err != nil {
			return nil, err
		}
		return pd.Dial("tcp", addr)
	case "http", "https":
		c, err := d.Dial("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
		if u.User != nil {
			pw, _ := u.User.Password()
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)) + "\r\n"
		}
		req += "\r\n"
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(req)); err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			c.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			c.Close()
			return nil, fmt.Errorf("bridge CONNECT: %s", resp.Status)
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}
	return nil, fmt.Errorf("unsupported bridge scheme %q", u.Scheme)
}
