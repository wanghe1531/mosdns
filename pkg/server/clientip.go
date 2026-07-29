package server

import (
	"net"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
)

// EDNS0ClientIPCode is a private-use EDNS option code (IANA local/experimental
// range 65001-65534). A trusted local forwarder (xdp-tool) uses it to convey the
// original client IP of a forwarded (cache-miss) query, so mosdns audit logs can
// attribute the query to the real client instead of the forwarder. It is used
// ONLY for auditing — it never affects routing or the client_ip matcher.
const EDNS0ClientIPCode = 65001

var (
	localAddrsOnce sync.Once
	localAddrs     map[netip.Addr]struct{}
)

func initLocalAddrs() {
	localAddrs = make(map[netip.Addr]struct{})
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if na, ok := netip.AddrFromSlice(ipn.IP); ok {
				localAddrs[na.Unmap()] = struct{}{}
			}
		}
	}
}

// trustedLocalSource reports whether src is this host itself (loopback or one of
// its own interface addresses) — i.e. the query came from a local forwarder, not
// a LAN client. xdp-tool dials the router's own address, so its source is local;
// a LAN client's source is not, which prevents clients forging their identity.
func trustedLocalSource(src netip.Addr) bool {
	if src.IsLoopback() {
		return true
	}
	localAddrsOnce.Do(initLocalAddrs)
	_, ok := localAddrs[src.Unmap()]
	return ok
}

// ExtractClientIP pulls the private client-IP EDNS option out of q and strips it
// (always strips, so a forged option never leaks upstream). It returns the
// conveyed client address only when q came from a trusted local source; ok=false
// otherwise, in which case the caller must keep the transport ClientAddr.
func ExtractClientIP(q *dns.Msg, src netip.Addr) (netip.Addr, bool) {
	opt := q.IsEdns0()
	if opt == nil {
		return netip.Addr{}, false
	}
	var found netip.Addr
	var got bool
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if l, isLocal := o.(*dns.EDNS0_LOCAL); isLocal && l.Code == EDNS0ClientIPCode {
			if a, good := netip.AddrFromSlice(l.Data); good {
				found, got = a.Unmap(), true
			}
			continue // strip regardless of trust
		}
		kept = append(kept, o)
	}
	opt.Option = kept
	if !got || !trustedLocalSource(src) {
		return netip.Addr{}, false
	}
	return found, true
}
