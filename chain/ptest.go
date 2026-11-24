// v1.8.4 Bridge + Psiphon test: "libchain ptest -file F". No WARP account involved.
//
//	stage 1: every proxy (one per line, scheme://[user:pass@]host:port or host:port = auto-detected): proxy handshake
//	         + TLS handshake to a host abroad through it, -n in parallel, -hs seconds each.
//	stage 2: a real Psiphon connect through the -real fastest ones, -par at a time (default 3), each in a child
//	         "libchain run -upstream" with its own data dir (dir/ptest/<slot>), -timeout seconds (default 75), then
//	         one HTTPS request through its SOCKS port. Stops starting new ones after -keep passes.
//
// Output refers to proxies by line index only (lines may carry credentials):
//
//	PPROG done ok | PHS i ms scheme | PSTAGE2 n | PTRY i | PREAL i ms region | PFAIL i hs|psiphon reason | DONE
package main

import (
	"bufio"
	"flag"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func cmdPTest(args []string) int {
	fs := flag.NewFlagSet("ptest", flag.ExitOnError)
	file := fs.String("file", "", "file with one proxy per line")
	n := fs.Int("n", 50, "parallel handshakes (stage 1)")
	hs := fs.Int("hs", 8, "seconds per handshake")
	realN := fs.Int("real", 6, "proxies that get a real Psiphon connect (stage 2)")
	par := fs.Int("par", 3, "parallel Psiphon connects")
	keep := fs.Int("keep", 3, "stop after this many pass stage 2")
	to := fs.Int("timeout", 75, "seconds for each Psiphon connect")
	dir := fs.String("dir", ".", "data directory")
	region := fs.String("region", "", "Psiphon egress region")
	dns := fs.String("dns", "", "DNS servers")
	fs.Parse(args)
	setupDNS(*dns)
	b, err := os.ReadFile(*file)
	if err != nil {
		say("ERR %s", err)
		return 1
	}
	type cand struct {
		i  int
		u  *upstream
		ms int
	}
	var all []cand
	for i, line := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := parseUpstream(line)
		if err != nil {
			say("PFAIL %d hs %s", i, oneLine(err.Error()))
			continue
		}
		all = append(all, cand{i: i, u: u})
	}

	// stage 1
	var mu sync.Mutex
	var ok []cand
	var done, nOK atomic.Int32
	sem := make(chan struct{}, max(1, *n))
	var wg sync.WaitGroup
	for _, c := range all {
		wg.Add(1)
		go func(c cand) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := c.u.detect(time.Duration(*hs) * time.Second)
			d := done.Add(1)
			if err != nil {
				say("PFAIL %d hs %s", c.i, oneLine(err.Error()))
			} else {
				c.ms = ms
				nOK.Add(1)
				mu.Lock()
				ok = append(ok, c)
				mu.Unlock()
				say("PHS %d %d %s", c.i, ms, c.u.Scheme)
			}
			if d%10 == 0 || int(d) == len(all) {
				say("PPROG %d %d", d, nOK.Load())
			}
		}(c)
	}
	wg.Wait()
	sort.Slice(ok, func(a, b int) bool { return ok[a].ms < ok[b].ms })
	if len(ok) > *realN {
		ok = ok[:*realN]
	}
	say("PSTAGE2 %d", len(ok))

	// stage 2: child processes (Psiphon keeps process-wide state: one controller per process)
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	slots := make(chan int, max(1, *par))
	for s := 0; s < max(1, *par); s++ {
		slots <- s
	}
	var passed atomic.Int32
	var wg2 sync.WaitGroup
	for _, c := range ok {
		slot := <-slots
		if int(passed.Load()) >= *keep {
			slots <- slot
			break
		}
		wg2.Add(1)
		go func(c cand, slot int) {
			defer wg2.Done()
			defer func() { slots <- slot }()
			say("PTRY %d", c.i)
			ms, reg, err := psiphonThrough(self, c.u, filepath.Join(*dir, "ptest", strconv.Itoa(slot)), *region, *dns, *to)
			if err != nil {
				say("PFAIL %d psiphon %s", c.i, oneLine(err.Error()))
				return
			}
			passed.Add(1)
			say("PREAL %d %d %s", c.i, ms, reg)
		}(c, slot)
	}
	wg2.Wait()
	say("DONE")
	return 0
}

type errString string

func (e errString) Error() string { return string(e) }

// psiphonThrough runs "libchain run -upstream" in a child, waits for READY, probes one HTTPS request through it.
func psiphonThrough(self string, u *upstream, dir, region, dns string, timeoutS int) (int, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return -1, "", err
	}
	uf := filepath.Join(dir, "up.txt")
	line := u.Scheme + "://"
	if u.User != "" || u.Pass != "" {
		line += u.psiCred() + "@"
	}
	line += u.Host
	if err := os.WriteFile(uf, []byte(line), 0o600); err != nil {
		return -1, "", err
	}
	defer os.Remove(uf)
	a := []string{"run", "-upstream", "@" + uf, "-dir", dir, "-psitimeout", strconv.Itoa(timeoutS), "-psipool", "1", "-keepalive", "0"}
	if region != "" {
		a = append(a, "-region", region)
	}
	if dns != "" {
		a = append(a, "-dns", dns)
	}
	cmd := exec.Command(self, a...)
	cmd.Env = append(os.Environ(), "CHAIN_WATCH_STDIN=1")
	stdin, _ := cmd.StdinPipe() // closing it ends the child (stdin EOF)
	outp, err := cmd.StdoutPipe()
	if err != nil {
		return -1, "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return -1, "", err
	}
	defer func() {
		stdin.Close()
		cmd.Process.Signal(os.Interrupt)
		t := time.AfterFunc(5*time.Second, func() { cmd.Process.Kill() })
		cmd.Wait()
		t.Stop()
	}()
	type ev struct {
		port      int
		reg, fail string
	}
	ch := make(chan ev, 4)
	go func() {
		sc := bufio.NewScanner(outp)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		reg, last := "", ""
		for sc.Scan() {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "PSI_ACTIVE "):
				reg = strings.TrimSpace(l[11:])
			case strings.HasPrefix(l, "READY "):
				p, _ := strconv.Atoi(strings.TrimSpace(l[6:]))
				ch <- ev{port: p, reg: reg}
			case strings.HasPrefix(l, "CONFIG_ERR "), strings.HasPrefix(l, "ERR "):
				last = l[strings.Index(l, " ")+1:]
			case strings.HasPrefix(l, "PSI_UPSTREAM_ERR "):
				last = "upstream: " + l[17:]
			}
		}
		if last == "" {
			last = "psiphon exited"
		}
		ch <- ev{fail: last}
	}()
	t0 := time.Now()
	select {
	case e := <-ch:
		if e.fail != "" {
			return -1, "", errString(e.fail)
		}
		if e.reg == "" || e.reg == "<nil>" {
			e.reg = "-"
		}
		ms, err := probe(e.port, 15*time.Second)
		if err != nil {
			return -1, "", errString("psiphon up after " + strconv.Itoa(int(time.Since(t0).Seconds())) + " s, no data: " + err.Error())
		}
		return ms, e.reg, nil
	case <-time.After(time.Duration(timeoutS+15) * time.Second):
		return -1, "", errString("no Psiphon tunnel in " + strconv.Itoa(timeoutS) + " s")
	}
}

// psiCred: user:pass %-encoded (parseUpstream decodes it again in the child).
func (u *upstream) psiCred() string {
	return url.UserPassword(u.User, u.Pass).String()
}
