// Package forward implements a forwarding proxy. It caches an upstream net.Conn for some time, so if the same
// client returns the upstream's Conn will be precached. Depending on how you benchmark this looks to be
// 50% faster than just opening a new connection for every client. It works with UDP and TCP and uses
// inband healthchecking.
package forward

import (
	"context"
	"crypto/tls"
	"github.com/coredns/coredns/plugin/pkg/proxypool"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("forward")

const (
	defaultExpire = 10 * time.Second
)

// Forward represents a plugin instance that can proxy requests to another (DNS) server. It has a list
// of proxies each representing one upstream proxy.
type Forward struct {
	from    string
	ignored []string

	nextAlternateRcodes []int

	tlsConfig     *tls.Config
	tlsServerName string
	expire        time.Duration

	processor RequestProcessor
	pool      *proxypool.ProxyPool

	tapPlugins []*dnstap.Dnstap // when dnstap plugins are loaded, we use to this to send messages out.

	Next plugin.Handler
}

// New returns a new Forward.
func New() *Forward {
	f := &Forward{
		tlsConfig: new(tls.Config),
		expire:    defaultExpire,
		from:      ".",
		pool:      proxypool.New(),
		processor: DefaultRequestProcessor{},
	}
	return f
}

// SetProxy appends p to the proxy list and starts healthchecking.
func (f *Forward) SetProxy(p *proxy.Proxy) {
	f.pool.AddProxy(p)
}

// SetProxyOptions setup proxy options
func (f *Forward) SetProxyOptions(opts proxy.Options) {
	proxypool.WithProxyOptions(opts)(f.pool)
}

// SetTapPlugin appends one or more dnstap plugins to the tap plugin list.
func (f *Forward) SetTapPlugin(tapPlugin *dnstap.Dnstap) {
	f.tapPlugins = append(f.tapPlugins, tapPlugin)
	if nextPlugin, ok := tapPlugin.Next.(*dnstap.Dnstap); ok {
		f.SetTapPlugin(nextPlugin)
	}
}

// Len returns the number of configured proxies.
func (f *Forward) Len() int { return f.pool.ProxyCount() }

// Name implements plugin.Handler.
func (f *Forward) Name() string { return "forward" }

// ServeDNS implements plugin.Handler.
func (f *Forward) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if !f.match(state) {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	start := time.Now()

	ret, err, upstreamAddr := f.processor.ProcessRequest(ctx, state, f.pool.Connect)

	// Processors can initiate fallthrough
	if err == FallthroughError {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	// Upstream addr may be an empty string
	metadata.SetValueFunc(ctx, "forward/upstream", func() string {
		return upstreamAddr
	})

	// Return if error
	if err != nil {
		if err == f.pool.ErrLimitExceeded {
			return dns.RcodeRefused, err
		}
		if err == proxypool.ErrMalformedResponse {
			ret = new(dns.Msg)
			ret.SetRcode(state.Req, dns.RcodeFormatError)

			w.WriteMsg(ret)
			return 0, nil
		}

		return dns.RcodeServerFailure, err
	}

	if len(f.tapPlugins) != 0 {
		toDnstap(ctx, f, upstreamAddr, state, f.pool.Opts(), ret, start)
	}

	// Check if we have an alternate Rcode defined, check if we match on the code
	for _, alternateRcode := range f.nextAlternateRcodes {
		if alternateRcode == ret.Rcode && f.Next != nil { // In case we do not have a Next handler, just continue normally
			if _, ok := f.Next.(*Forward); ok { // Only continue if the next forwarder is also a Forwarder
				return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
			}
		}
	}

	w.WriteMsg(ret)
	return 0, nil
}

func (f *Forward) match(state request.Request) bool {
	if !plugin.Name(f.from).Matches(state.Name()) || !f.isAllowedDomain(state.Name()) || !f.processor.Match(state) {
		return false
	}

	return true
}

func (f *Forward) isAllowedDomain(name string) bool {
	if dns.Name(name) == dns.Name(f.from) {
		return true
	}

	for _, ignore := range f.ignored {
		if plugin.Name(ignore).Matches(name) {
			return false
		}
	}
	return true
}

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (f *Forward) ForceTCP() bool { return f.pool.ForceTCP() }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (f *Forward) PreferUDP() bool { return f.pool.PreferUDP() }

// List returns a set of proxies to be used for this client depending on the policy in f.
func (f *Forward) List() []*proxy.Proxy { return f.pool.List() }

// Options holds various Options that can be set.
type Options struct {
	// ForceTCP use TCP protocol for upstream DNS request. Has precedence over PreferUDP flag
	ForceTCP bool
	// PreferUDP use UDP protocol for upstream DNS request.
	PreferUDP bool
	// HCRecursionDesired sets recursion desired flag for Proxy healthcheck requests
	HCRecursionDesired bool
	// HCDomain sets domain for Proxy healthcheck requests
	HCDomain string
}

var defaultTimeout = 5 * time.Second
