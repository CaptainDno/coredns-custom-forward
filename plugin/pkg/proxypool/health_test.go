package proxypool

import (
	"context"
	"github.com/coredns/coredns/request"

	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestHealth(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	i := uint32(0)
	q := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if atomic.LoadUint32(&q) == 0 { //drop the first query to trigger health-checking
			atomic.AddUint32(&q, 1)
			return
		}
		if r.Question[0].Name == "." && r.RecursionDesired == true {
			atomic.AddUint32(&i, 1)
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		w.WriteMsg(ret)
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealth", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)

	pool := New(WithTimeout(defaultTimeout))
	pool.AddProxy(p)

	defer p.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 1 {
		t.Errorf("Expected number of health checks with RecursionDesired==true to be %d, got %d", 1, i1)
	}
}

func TestHealthTCP(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	i := uint32(0)
	q := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if atomic.LoadUint32(&q) == 0 { //drop the first query to trigger health-checking
			atomic.AddUint32(&q, 1)
			return
		}
		if r.Question[0].Name == "." && r.RecursionDesired == true {
			atomic.AddUint32(&i, 1)
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		w.WriteMsg(ret)
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealthTCP", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetTCPTransport()

	pool := New(WithTimeout(defaultTimeout))
	pool.AddProxy(p)
	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{TCP: true},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 1 {
		t.Errorf("Expected number of health checks with RecursionDesired==true to be %d, got %d", 1, i1)
	}
}

func TestHealthNoRecursion(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	i := uint32(0)
	q := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if atomic.LoadUint32(&q) == 0 { //drop the first query to trigger health-checking
			atomic.AddUint32(&q, 1)
			return
		}
		if r.Question[0].Name == "." && r.RecursionDesired == false {
			atomic.AddUint32(&i, 1)
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		w.WriteMsg(ret)
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealthNoRecursion", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetRecursionDesired(false)

	pool := New(WithTimeout(defaultTimeout))
	pool.AddProxy(p)

	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 1 {
		t.Errorf("Expected number of health checks with RecursionDesired==false to be %d, got %d", 1, i1)
	}
}

func TestHealthTimeout(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	i := uint32(0)
	q := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == "." {
			// health check, answer
			atomic.AddUint32(&i, 1)
			ret := new(dns.Msg)
			ret.SetReply(r)
			w.WriteMsg(ret)
			return
		}
		if atomic.LoadUint32(&q) == 0 { //drop only first query
			atomic.AddUint32(&q, 1)
			return
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		w.WriteMsg(ret)
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealthTimeout", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)

	pool := New(WithTimeout(defaultTimeout))
	pool.AddProxy(p)

	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 1 {
		t.Errorf("Expected number of health checks to be %d, got %d", 1, i1)
	}
}

func TestHealthMaxFails(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond
	//,hcInterval = 10 * time.Millisecond

	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		// timeout
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealthMaxFails", s.Addr, transport.DNS)
	p.SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)

	pool := New(
		WithHealthCheckInterval(defaultTimeout),
		WithMaxFails(2),
	)

	pool.AddProxy(p)

	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(100 * time.Millisecond)
	fails := p.Fails()
	if !p.Down(2) {
		t.Errorf("Expected Proxy fails to be greater than %d, got %d", 2, fails)
	}
}

func TestHealthNoMaxFails(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	i := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == "." {
			// health check, answer
			atomic.AddUint32(&i, 1)
			ret := new(dns.Msg)
			ret.SetReply(r)
			w.WriteMsg(ret)
		}
	})
	defer s.Close()

	p := proxy.NewProxy("TestHealthNoMaxFails", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)

	pool := New(
		WithMaxFails(0),
		WithTimeout(defaultTimeout),
	)

	pool.AddProxy(p)

	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 0 {
		t.Errorf("Expected number of health checks to be %d, got %d", 0, i1)
	}
}

func TestHealthDomain(t *testing.T) {
	defaultTimeout := 10 * time.Millisecond

	hcDomain := "example.org."
	i := uint32(0)
	q := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if atomic.LoadUint32(&q) == 0 { //drop the first query to trigger health-checking
			atomic.AddUint32(&q, 1)
			return
		}
		if r.Question[0].Name == hcDomain && r.RecursionDesired == true {
			atomic.AddUint32(&i, 1)
		}
		ret := new(dns.Msg)
		ret.SetReply(r)
		w.WriteMsg(ret)
	})
	defer s.Close()
	p := proxy.NewProxy("TestHealthDomain", s.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetWriteTimeout(10 * time.Millisecond)
	p.GetHealthchecker().SetDomain(hcDomain)

	pool := New(
		WithTimeout(defaultTimeout))

	pool.AddProxy(p)
	defer pool.Stop()

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	time.Sleep(20 * time.Millisecond)
	i1 := atomic.LoadUint32(&i)
	if i1 != 1 {
		t.Errorf("Expected number of health checks with Domain==%s to be %d, got %d", hcDomain, 1, i1)
	}
}

func TestAllUpstreamsDown(t *testing.T) {
	qs := uint32(0)
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		// count non-healthcheck queries
		if r.Question[0].Name != "." {
			atomic.AddUint32(&qs, 1)
		}
		// timeout
	})
	defer s.Close()

	s1 := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		// count non-healthcheck queries
		if r.Question[0].Name != "." {
			atomic.AddUint32(&qs, 1)
		}
		// timeout
	})
	defer s1.Close()

	p := proxy.NewProxy("TestHealthAllUpstreamsDown", s.Addr, transport.DNS)
	p1 := proxy.NewProxy("TestHealthAllUpstreamsDown2", s1.Addr, transport.DNS)
	p.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)
	p1.GetHealthchecker().SetReadTimeout(10 * time.Millisecond)

	pool := New(
		WithMaxFails(1),
		WithFailFast(true),
		WithProxies(p, p1),
	)

	pool.Start()

	// Make proxys fail by checking health twice
	// i.e, fails > maxfails
	for range 1 + 1 {
		p.GetHealthchecker().Check(p)
		p1.GetHealthchecker().Check(p1)
	}

	defer pool.Stop()

	// Check if all proxies are down
	if !p.Down(1) || !p1.Down(1) {
		t.Fatalf("Expected all proxies to be down")
	}
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	_, err, _ := pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})

	if err != ErrNoHealthy {
		t.Errorf("Expected error message: no healthy proxies, Got: %s", err.Error())
	}

	q1 := atomic.LoadUint32(&qs)
	if q1 != 0 {
		t.Errorf("Expected queries to the upstream: 0, Got: %d", q1)
	}

	// set failfast to false to check if queries get answered

	WithFailFast(false)(pool)

	req = new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	_, err, _ = pool.Connect(context.TODO(), request.Request{
		Req: req,
		W:   &test.ResponseWriter{},
	})
	if err == ErrNoHealthy {
		t.Error("Unexpected error message: no healthy proxies")
	}

	q1 = atomic.LoadUint32(&qs)
	if q1 != 1 {
		t.Errorf("Expected queries to the upstream: 1, Got: %d", q1)
	}
}
