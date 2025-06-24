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

// YggRequestProcessor only supports AAAA requests
// It returns AAAA records that point to Yggdrasil ip addresses
// This addresses must be present in TXT record
type YggRequestProcessor struct{}

func (y YggRequestProcessor) Match(state request.Request) bool {
	return state.QType() == dns.TypeAAAA
}

func (y YggRequestProcessor) ProcessRequest(ctx context.Context, state request.Request, connect ConnectFn) (*dns.Msg, error, string) {
	state.Req.Question[0].Qtype = dns.TypeTXT

	ret, err, upstream := connect(ctx, state)

	// Switch back to original
	state.Req.Question[0].Qtype = dns.TypeAAAA

	if err != nil || ret.Rcode != dns.RcodeSuccess {
		return ret, err, upstream
	}

	answers := make([]dns.RR, 0, 1)

	for _, rr := range ret.Answer {
		if rr.Header().Rrtype == dns.TypeTXT {
			record := rr.(*dns.TXT)

			if s, found := strings.CutPrefix(record.Txt[0], "yggaddr="); found {
				// We have found needed record

				hdr := dns.RR_Header{
					Name:   record.Hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    record.Hdr.Ttl,
				}

				answers, err = appendYggAddresses(answers, s, hdr)
				if err != nil {
					if err == InvalidIPAddressError {
						formerr := new(dns.Msg)
						formerr.SetRcode(state.Req, dns.RcodeServerFailure)
						return formerr, nil, upstream
					}
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

				// Exit loop over txt records, only one yggaddr record is allowed
				break
			}
		}
	}

	// Set new answer RRs
	ret.Answer = answers

	return ret, nil, upstream
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

// See Yggdrasil documentation
func getYggSubnet() *net.IPNet {
	_, v, err := net.ParseCIDR("0200::/7")

	if err != nil {
		panic(err)
	}

	return v
}

var YGGSubnet = getYggSubnet()
