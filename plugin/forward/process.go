package forward

import (
	"context"
	"errors"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"net"
	"slices"
	"strings"
)

type ConnectFn func(ctx context.Context, state request.Request) (*dns.Msg, error, string)

type RequestProcessor interface {
	// ProcessRequest returns dns response or error
	ProcessRequest(ctx context.Context, state request.Request, connectFn ConnectFn) (*dns.Msg, error, string)
	// Match returns true if this processor supports request, false if not
	Match(state request.Request) bool
}

type DefaultRequestProcessor struct{}

func (d DefaultRequestProcessor) Match(state request.Request) bool {
	return true
}

func (d DefaultRequestProcessor) ProcessRequest(ctx context.Context, state request.Request, connectFn ConnectFn) (*dns.Msg, error, string) {
	return connectFn(ctx, state)
}

// YggRequestProcessor only supports AAAA and A requests
// It returns AAAA records that point to Yggdrasil ip addresses
// This addresses must be present in TXT record
type YggRequestProcessor struct {
}

func (y YggRequestProcessor) Match(state request.Request) bool {
	return state.QType() == dns.TypeAAAA || state.QType() == dns.TypeA
}

func (y YggRequestProcessor) ProcessRequest(ctx context.Context, state request.Request, connect ConnectFn) (*dns.Msg, error, string) {

	oQtype := state.QType()

	state.Req.Question[0].Qtype = dns.TypeTXT

	ret, err, upstream := connect(ctx, state)

	// Switch back to original
	state.Req.Question[0].Qtype = oQtype

	if err != nil || ret.Rcode != dns.RcodeSuccess {
		return ret, err, upstream
	}

	// Scan TXT records
	for _, rr := range ret.Answer {
		if rr.Header().Rrtype == dns.TypeTXT {
			record := rr.(*dns.TXT)

			if s, found := strings.CutPrefix(record.Txt[0], "yggaddr="); found {

				// If yggaddr record exists, do not return IPv4 addresses, because they are outside of Yggdrasil
				if oQtype == dns.TypeA {
					e := new(dns.Msg)
					e.SetRcode(state.Req, dns.RcodeSuccess)
					return e, nil, upstream
				}

				// We have found the needed record
				answers := make([]dns.RR, 0, 1)

				// Header will be same for all returned records (if any)
				hdr := dns.RR_Header{
					Name:   record.Hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    record.Hdr.Ttl,
				}

				answers, err = appendYggAddresses(answers, s, hdr)

				// If yggaddr record is malformed, we do not fall through silently, we return actual error
				// Plugin may be additionally configured to fall though on ServerFailure
				if err == InvalidIPAddressError || len(answers) == 0 {
					formerr := new(dns.Msg)
					formerr.SetRcode(state.Req, dns.RcodeServerFailure)
					return formerr, nil, upstream
				}

				if err != nil {
					return nil, err, upstream
				}

				// Repeat parsing for all other strings in TXT record
				for _, s = range record.Txt[1:] {
					answers, err = appendYggAddresses(answers, s, hdr)

					if err != nil {
						if err == InvalidIPAddressError {
							formerr := new(dns.Msg)
							formerr.SetRcode(state.Req, dns.RcodeServerFailure)
							return formerr, nil, upstream
						}
						return nil, err, upstream
					}
				}

				// Return results
				reply := new(dns.Msg)
				reply.SetReply(state.Req)
				reply.Answer = answers
				return reply, nil, upstream
			}
		}
	}

	// This happens if there is no Yggdrasil record for the domain
	return nil, FallthroughError, upstream
}

func appendYggAddresses(answers []dns.RR, str string, hdr dns.RR_Header) ([]dns.RR, error) {
	split := strings.Fields(str)

	answers = slices.Grow(answers, len(split))

	for _, raw := range split {
		ip := net.ParseIP(raw)

		// Return error if ip address is malformed or is not a valid Yggdrasil address
		if ip == nil || !YGGSubnet.Contains(ip) {
			return answers, InvalidIPAddressError
		}

		// Create mew RR and append to slice
		r := new(dns.AAAA)
		r.Hdr = hdr
		r.AAAA = ip

		answers = append(answers, r)
	}

	return answers, nil
}

var InvalidIPAddressError = errors.New("invalid IP Address")
var FallthroughError = errors.New("fallthrough")

// See Yggdrasil documentation
func getYggSubnet() *net.IPNet {
	_, v, err := net.ParseCIDR("0200::/7")

	if err != nil {
		panic(err)
	}

	return v
}

var YGGSubnet = getYggSubnet()
