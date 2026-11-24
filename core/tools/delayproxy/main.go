// Test tool: TCP relay that adds a fixed one-way delay to every chunk in both directions (a userspace stand-in for
// `tc netem delay`, which needs root). Order is preserved; throughput is not limited. The first client->server chunk
// is held one extra round trip to model the TCP handshake the client already finished with this relay.
//
//	go run ./tools/delayproxy -listen 127.0.0.1:9443 -to 127.0.0.1:8443 -delay 500ms
package main

import (
	"flag"
	"log"
	"math/rand"
	"sync/atomic"
	"net"
	"time"
)

type chunk struct {
	b  []byte
	at time.Time
}

var idleBH time.Duration

// idleConn tracks the last client->server activity; once idle longer than idleBH the connection is black-holed
// (nothing forwarded any more, nothing closed) — models DPI silently killing idle TLS connections.
type idleConn struct {
	last atomic.Int64
	dead atomic.Bool
}

func (ic *idleConn) blackholed() bool {
	if idleBH <= 0 {
		return false
	}
	if ic.dead.Load() {
		return true
	}
	if time.Since(time.Unix(0, ic.last.Load())) > idleBH {
		ic.dead.Store(true)
		return true
	}
	return false
}

var spikeP float64
var spikeD time.Duration

// pipe forwards src->dst with a fixed delay; with probability spikeP a chunk is held spikeD longer (models a lost
// segment waiting for TCP retransmission on a lossy mobile path), and every later chunk queues behind it.
func pipe(dst, src net.Conn, delay, firstExtra time.Duration, ic *idleConn, up bool) {
	q := make(chan chunk, 4096)
	go func() {
		defer close(q)
		first := true
		for {
			buf := make([]byte, 32*1024)
			n, err := src.Read(buf)
			if n > 0 && ic.blackholed() {
				continue // swallowed
			}
			if n > 0 && up {
				ic.last.Store(time.Now().UnixNano())
			}
			if n > 0 {
				d := delay
				if first {
					d += firstExtra
					first = false
				}
				if spikeP > 0 && rand.Float64() < spikeP {
					d += spikeD
				}
				q <- chunk{buf[:n], time.Now().Add(d)}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range q {
		time.Sleep(time.Until(c.at))
		if _, err := dst.Write(c.b); err != nil {
			break
		}
	}
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	} else {
		dst.Close()
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "listen address")
	to := flag.String("to", "127.0.0.1:8443", "target")
	delay := flag.Duration("delay", 500*time.Millisecond, "one-way delay")
	flag.Float64Var(&spikeP, "spike", 0, "probability that a chunk is held -spikedelay longer (loss/retransmit model)")
	flag.DurationVar(&spikeD, "spikedelay", 3*time.Second, "extra delay of a spiked chunk")
	flag.DurationVar(&idleBH, "idlebh", 0, "black-hole a connection after this long without client data (0 = off)")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("delayproxy %s -> %s, one-way %v (RTT %v), spike %.2f x %v", *listen, *to, *delay, 2**delay, spikeP, spikeD)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			// the upstream connect itself also costs one RTT on a real path
			time.Sleep(2 * *delay)
			u, err := net.Dial("tcp", *to)
			if err != nil {
				c.Close()
				return
			}
			done := make(chan struct{}, 2)
			ic := &idleConn{}
			ic.last.Store(time.Now().UnixNano())
			go func() { pipe(u, c, *delay, 0, ic, true); done <- struct{}{} }()
			go func() { pipe(c, u, *delay, 0, ic, false); done <- struct{}{} }()
			<-done
			<-done
			c.Close()
			u.Close()
		}(c)
	}
}
