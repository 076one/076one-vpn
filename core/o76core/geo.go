// v1.5 offline IP -> country check for the bridge "Iran only" option. ir_v4.zone = aggregated IPv4 blocks of Iran
// from ipdeny.com (www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone, fetched 2026-11-22). Only IR is
// bundled; it is a light approximation (geolocation drifts), used to drop non-Iranian proxies before testing.
//
//	ipfilter -country IR      reads proxy URLs / ip:port lines on stdin, prints the ones located in the country
package main

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"flag"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
)

//go:embed ir_v4.zone
var irZone string

type ipRange struct{ lo, hi uint32 }

var (
	geoOnce sync.Once
	geoIR   []ipRange
)

func loadGeo() {
	for _, l := range strings.Split(irZone, "\n") {
		p, err := netip.ParsePrefix(strings.TrimSpace(l))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		a := p.Masked().Addr().As4()
		lo := binary.BigEndian.Uint32(a[:])
		hi := lo | (uint32(0xffffffff) >> uint(p.Bits()))
		if p.Bits() == 0 {
			hi = 0xffffffff
		}
		geoIR = append(geoIR, ipRange{lo, hi})
	}
	sort.Slice(geoIR, func(i, j int) bool { return geoIR[i].lo < geoIR[j].lo })
}

// inCountry reports whether host (an IPv4 literal) lies in the bundled ranges of cc (only "IR" is bundled).
func inCountry(host, cc string) bool {
	if !strings.EqualFold(cc, "IR") {
		return false
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || !ip.Unmap().Is4() {
		return false
	}
	geoOnce.Do(loadGeo)
	a := ip.Unmap().As4()
	v := binary.BigEndian.Uint32(a[:])
	i := sort.Search(len(geoIR), func(i int) bool { return geoIR[i].hi >= v })
	return i < len(geoIR) && geoIR[i].lo <= v
}

func cmdIPFilter(args []string) {
	fs := flag.NewFlagSet("ipfilter", flag.ExitOnError)
	cc := fs.String("country", "IR", "country code (only IR is bundled)")
	_ = fs.Parse(args)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			continue
		}
		if b, err := parseBridge(l, "auto"); err == nil && inCountry(b.host, *cc) {
			out("%s", l)
		}
	}
	out("DONE")
}
