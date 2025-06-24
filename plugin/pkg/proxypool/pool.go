package proxypool

import (
	"context"
	"errors"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
	"sync/atomic"
	"time"
)

type ProxyPool struct {
	concurrent int64

	proxies             []*proxy.Proxy
	policy              Policy
	healthCheckInterval time.Duration

	opts proxy.Options

	maxConcurrent    int64
	ErrLimitExceeded error

	timeout                    time.Duration
	maxfails                   uint32
	failfastUnhealthyUpstreams bool
}

func New(options ...func(pool *ProxyPool)) *ProxyPool {
	pool := &ProxyPool{
		concurrent:          0,
		proxies:             make([]*proxy.Proxy, 0),
		policy:              new(Random),
		healthCheckInterval: 1 * time.Second,
		opts: proxy.Options{
			ForceTCP:           false,
			PreferUDP:          false,
			HCRecursionDesired: true,
			HCDomain:           ".",
		},
		maxConcurrent:              0,
		ErrLimitExceeded:           errors.New("max concurrent requests exceeded"),
		maxfails:                   2,
		failfastUnhealthyUpstreams: false,
	}

	for _, o := range options {
		o(pool)
	}

	return pool
}

func WithProxyOptions(opts proxy.Options) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.opts = opts
	}
}

func WithHealthCheckInterval(interval time.Duration) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.healthCheckInterval = interval
	}
}

func WithMaxConcurrent(concurrent int64) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.maxConcurrent = concurrent
	}
}

func WithMaxFails(maxfails uint32) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.maxfails = maxfails
	}
}

func WithProxies(proxy ...*proxy.Proxy) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.proxies = append(pool.proxies, proxy...)
	}
}

func WithPolicy(policy Policy) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.policy = policy
	}
}

func WithFailFast(failfastUnhealthyUpstreams bool) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.failfastUnhealthyUpstreams = failfastUnhealthyUpstreams
	}
}

func WithTimeout(timeout time.Duration) func(pool *ProxyPool) {
	return func(pool *ProxyPool) {
		pool.timeout = timeout
	}
}

func (p *ProxyPool) AddProxy(proxy *proxy.Proxy) {
	p.proxies = append(p.proxies, proxy)
	proxy.Start(p.healthCheckInterval)
}

// Connect to one of the available upstreams and query it
// Automatically finds healthy upstreams
// Returns upstream.Addr() as string for convenience, or empty stream if no upstream was selected
func (p *ProxyPool) Connect(ctx context.Context, state request.Request) (*dns.Msg, error, string) {

	// Check concurrency limits
	if p.maxConcurrent > 0 {
		count := atomic.AddInt64(&(p.concurrent), 1)
		defer atomic.AddInt64(&(p.concurrent), -1)

		if count > p.maxConcurrent {
			maxConcurrentRejectCount.Add(1)
			return nil, p.ErrLimitExceeded, ""
		}
	}

	fails := 0
	var span, child ot.Span
	var upstreamErr error
	var upstream *proxy.Proxy
	span = ot.SpanFromContext(ctx)
	i := 0

	list := p.List()

	deadline := time.Now().Add(p.timeout)

	// Retry loop
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if i >= len(list) {
			// reached the end of list, reset to begin
			i = 0
			fails = 0
		}

		upstream = list[i]
		i++

		if upstream.Down(p.maxfails) {
			fails++
			if fails < len(p.proxies) {
				continue
			}

			healthcheckBrokenCount.Add(1)
			// All upstreams are dead, return servfail if all upstreams are down
			if p.failfastUnhealthyUpstreams {
				break
			}
			// assume healthcheck is completely broken and randomly
			// select an upstream to connect to.
			r := new(Random)
			upstream = r.List(p.proxies)[0]
		}

		if span != nil {
			child = span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
			otext.PeerAddress.Set(child, upstream.Addr())
			ctx = ot.ContextWithSpan(ctx, child)
		}

		var (
			ret *dns.Msg
			err error
		)
		opts := p.opts

		for {
			ret, err = upstream.Connect(ctx, state, opts)

			if err == ErrCachedClosed { // Remote side closed conn, can only happen with TCP.
				continue
			}
			// Retry with TCP if truncated and prefer_udp configured.
			if ret != nil && ret.Truncated && !opts.ForceTCP && opts.PreferUDP {
				opts.ForceTCP = true
				continue
			}
			break
		}

		if child != nil {
			child.Finish()
		}

		upstreamErr = err

		if err != nil {
			// Kick off health check to see if *our* upstream is broken.
			if p.maxfails != 0 {
				upstream.Healthcheck()
			}

			if fails < len(p.proxies) {
				continue
			}
			break
		}

		if !state.Match(ret) {
			debug.Hexdumpf(ret, "Wrong reply for id: %d, %s %d", ret.Id, state.QName(), state.QType())
			return nil, ErrMalformedResponse, upstream.Addr()
		}

		return ret, nil, upstream.Addr()
	}

	// upstream is not null here, see the loop body
	if upstreamErr != nil {
		return nil, upstreamErr, upstream.Addr()
	}

	// No healthy upstreams found
	return nil, ErrNoHealthy, ""
}

func (p *ProxyPool) Start() {
	for _, upstream := range p.proxies {
		upstream.Start(p.healthCheckInterval)
	}
}

func (p *ProxyPool) Stop() {
	for _, upstream := range p.proxies {
		upstream.Stop()
	}
}

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (p *ProxyPool) ForceTCP() bool { return p.opts.ForceTCP }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (p *ProxyPool) PreferUDP() bool { return p.opts.PreferUDP }

func (p *ProxyPool) ProxyCount() int {
	return len(p.proxies)
}

func (p *ProxyPool) List() []*proxy.Proxy { return p.policy.List(p.proxies) }

func (p *ProxyPool) Opts() proxy.Options { return p.opts }

func (p *ProxyPool) Policy() Policy { return p.policy }

func (p *ProxyPool) HealthcheckInterval() time.Duration { return p.healthCheckInterval }

func (p *ProxyPool) FailFast() bool { return p.failfastUnhealthyUpstreams }

func (p *ProxyPool) MaxFails() uint32 { return p.maxfails }

func (p *ProxyPool) Proxies() []*proxy.Proxy { return p.proxies }

func (p *ProxyPool) MaxConcurrent() int64 { return p.maxConcurrent }

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
	// ErrMalformedResponse means that response from upstream did not match query
	ErrMalformedResponse = errors.New("malformed response")
)
