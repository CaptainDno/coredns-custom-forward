package forward

import (
	"crypto/tls"
	"fmt"
	"github.com/coredns/coredns/plugin/pkg/proxypool"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"

	"github.com/miekg/dns"
)

func init() {
	plugin.Register("forward", setup)
}

func setup(c *caddy.Controller) error {
	fs, err := parseForward(c)
	if err != nil {
		return plugin.Error("forward", err)
	}
	for i := range fs {
		f := fs[i]
		if f.Len() > max {
			return plugin.Error("forward", fmt.Errorf("more than %d TOs configured: %d", max, f.Len()))
		}

		if i == len(fs)-1 {
			// last forward: point next to next plugin
			dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
				f.Next = next
				return f
			})
		} else {
			// middle forward: point next to next forward
			nextForward := fs[i+1]
			dnsserver.GetConfig(c).AddPlugin(func(plugin.Handler) plugin.Handler {
				f.Next = nextForward
				return f
			})
		}

		c.OnStartup(func() error {
			return f.OnStartup()
		})
		c.OnStartup(func() error {
			if taph := dnsserver.GetConfig(c).Handler("dnstap"); taph != nil {
				f.SetTapPlugin(taph.(*dnstap.Dnstap))
			}
			return nil
		})

		c.OnShutdown(func() error {
			return f.OnShutdown()
		})
	}

	return nil
}

// OnStartup starts a goroutines for all proxies.
func (f *Forward) OnStartup() (err error) {
	f.pool.Start()
	log.Infof("Started forward plugin with %d upstreams", f.Len())
	return nil
}

// OnShutdown stops all configured proxies.
func (f *Forward) OnShutdown() error {
	f.pool.Stop()
	return nil
}

func parseForward(c *caddy.Controller) ([]*Forward, error) {
	var fs = []*Forward{}
	for c.Next() {
		f, err := parseStanza(c)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}
	return fs, nil
}

func parseStanza(c *caddy.Controller) (*Forward, error) {
	f := New()

	if !c.Args(&f.from) {
		return f, c.ArgErr()
	}
	origFrom := f.from
	zones := plugin.Host(f.from).NormalizeExact()
	if len(zones) == 0 {
		return f, fmt.Errorf("unable to normalize '%s'", f.from)
	}
	f.from = zones[0] // there can only be one here, won't work with non-octet reverse

	if len(zones) > 1 {
		log.Warningf("Unsupported CIDR notation: '%s' expands to multiple zones. Using only '%s'.", origFrom, f.from)
	}

	to := c.RemainingArgs()
	if len(to) == 0 {
		return f, c.ArgErr()
	}

	toHosts, err := parse.HostPortOrFile(to...)
	if err != nil {
		return f, err
	}

	transports := make([]string, len(toHosts))
	allowedTrans := map[string]bool{"dns": true, "tls": true}

	proxies := make([]*proxy.Proxy, 0, len(toHosts))

	for i, host := range toHosts {
		trans, h := parse.Transport(host)

		if !allowedTrans[trans] {
			return f, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host)
		}
		p := proxy.NewProxy("forward", h, trans)
		proxies = append(proxies, p)
		transports[i] = trans
	}

	for c.NextBlock() {
		if err := parseBlock(c, f); err != nil {
			return f, err
		}
	}

	if f.tlsServerName != "" {
		f.tlsConfig.ServerName = f.tlsServerName
	}

	// Initialize ClientSessionCache in tls.Config. This may speed up a TLS handshake
	// in upcoming connections to the same TLS server.
	f.tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(len(proxies))

	for i := range proxies {
		// Only set this for proxies that need it.
		if transports[i] == transport.TLS {
			proxies[i].SetTLSConfig(f.tlsConfig)
		}
		proxies[i].SetExpire(f.expire)
		proxies[i].GetHealthchecker().SetRecursionDesired(f.pool.Opts().HCRecursionDesired)
		// when TLS is used, checks are set to tcp-tls
		if f.pool.Opts().ForceTCP && transports[i] != transport.TLS {
			proxies[i].GetHealthchecker().SetTCPTransport()
		}
		proxies[i].GetHealthchecker().SetDomain(f.pool.Opts().HCDomain)
	}

	proxypool.WithProxies(proxies...)(f.pool)

	return f, nil
}

func parseBlock(c *caddy.Controller, f *Forward) error {
	config := dnsserver.GetConfig(c)

	poolOptions := make([]func(proxyPool *proxypool.ProxyPool), 0, 10)

	proxyOpts := proxy.Options{}

	switch c.Val() {
	case "except":
		ignore := c.RemainingArgs()
		if len(ignore) == 0 {
			return c.ArgErr()
		}
		for i := range ignore {
			f.ignored = append(f.ignored, plugin.Host(ignore[i]).NormalizeExact()...)
		}
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.ParseUint(c.Val(), 10, 32)
		if err != nil {
			return err
		}
		poolOptions = append(poolOptions, proxypool.WithMaxFails(uint32(n)))

	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("health_check can't be negative: %d", dur)
		}
		poolOptions = append(poolOptions, proxypool.WithHealthCheckInterval(dur))
		proxyOpts.HCDomain = "."

		for c.NextArg() {
			switch hcOpts := c.Val(); hcOpts {
			case "no_rec":
				proxyOpts.HCRecursionDesired = false
			case "domain":
				if !c.NextArg() {
					return c.ArgErr()
				}
				hcDomain := c.Val()
				if _, ok := dns.IsDomainName(hcDomain); !ok {
					return fmt.Errorf("health_check: invalid domain name %s", hcDomain)
				}
				proxyOpts.HCDomain = plugin.Name(hcDomain).Normalize()
			default:
				return fmt.Errorf("health_check: unknown option %s", hcOpts)
			}
		}

	case "force_tcp":
		if c.NextArg() {
			return c.ArgErr()
		}
		proxyOpts.ForceTCP = true
	case "prefer_udp":
		if c.NextArg() {
			return c.ArgErr()
		}
		proxyOpts.PreferUDP = true
	case "tls":
		args := c.RemainingArgs()
		if len(args) > 3 {
			return c.ArgErr()
		}

		for i := range args {
			if !filepath.IsAbs(args[i]) && config.Root != "" {
				args[i] = filepath.Join(config.Root, args[i])
			}
		}
		tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		f.tlsConfig = tlsConfig
	case "tls_servername":
		if !c.NextArg() {
			return c.ArgErr()
		}
		f.tlsServerName = c.Val()
	case "expire":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("expire can't be negative: %s", dur)
		}
		f.expire = dur
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		var policy proxypool.Policy
		switch x := c.Val(); x {
		case "random":
			policy = &proxypool.Random{}
		case "round_robin":
			policy = &proxypool.RoundRobin{}
		case "sequential":
			policy = &proxypool.Sequential{}
		default:
			return c.Errf("unknown policy '%s'", x)
		}
		poolOptions = append(poolOptions, proxypool.WithPolicy(policy))
	case "max_concurrent":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_concurrent can't be negative: %d", n)
		}

		poolOptions = append(poolOptions, proxypool.WithMaxConcurrent(int64(n)))
	case "next":
		args := c.RemainingArgs()
		if len(args) == 0 {
			return c.ArgErr()
		}

		for _, rcode := range args {
			var rc int
			var ok bool

			if rc, ok = dns.StringToRcode[strings.ToUpper(rcode)]; !ok {
				return fmt.Errorf("%s is not a valid rcode", rcode)
			}

			f.nextAlternateRcodes = append(f.nextAlternateRcodes, rc)
		}
	case "failfast_all_unhealthy_upstreams":
		args := c.RemainingArgs()
		if len(args) != 0 {
			return c.ArgErr()
		}

		poolOptions = append(poolOptions, proxypool.WithFailFast(true))
	// This is new parameter, it allows setting custom modes
	case "mode":
		if !c.NextArg() {
			return c.ArgErr()
		}

		switch m := c.Val(); m {
		case "normal":
			f.processor = DefaultRequestProcessor{}
		case "ygg":
			f.processor = YggRequestProcessor{}
		default:
			return c.Errf("unknown mode '%s'", m)
		}

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	poolOptions = append(poolOptions, proxypool.WithProxyOptions(proxyOpts))
	pool := proxypool.New(poolOptions...)

	f.pool = pool

	return nil
}

const max = 15 // Maximum number of upstreams.
