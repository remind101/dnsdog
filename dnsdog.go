package dnsdog

import (
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/patrickmn/go-cache"
)

const BPFFilter = "udp port 53"

type statsdClient interface {
	Count(name string, value int64, tags []string, rate float64) error
	Histogram(name string, value float64, tags []string, rate float64) error
}

// Watcher captures packets and logs stats to statsd.
type Watcher struct {
	packets <-chan gopacket.Packet
	statsd  statsdClient
	cache   *cache.Cache
}

// Watch starts watching iface and sends metrics to addr.
func Watch(iface, addr string) error {
	h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer h.Close()

	if err = h.SetBPFFilter(BPFFilter); err != nil {
		return err
	}

	c, err := statsd.NewBuffered(addr, 100)
	if err != nil {
		return err
	}
	defer c.Close()

	s := gopacket.NewPacketSource(h, h.LinkType())
	w := &Watcher{
		packets: s.Packets(),
		statsd:  c,
		cache:   cache.New(time.Second, time.Second),
	}
	return w.Watch()
}

func (w *Watcher) Watch() error {
	for p := range w.packets {
		if err := w.HandlePacket(p); err != nil {
			return err
		}
	}

	return nil
}

// HandlePacket handles a single packet.
func (w *Watcher) HandlePacket(p gopacket.Packet) error {
	dnsPacket, ok := p.ApplicationLayer().(*layers.DNS)
	if !ok {
		debug("packet error: %v", p)
		return nil
	}
	id := dnsPacket.ID

	if dnsPacket.QR {
		// This is a reply
		tags := []string{
			fmt.Sprintf("response_code:%s", response_code(dnsPacket.ResponseCode)),
		}
		w.statsd.Count("dns.reply", 1, tags, 1)

		t, ok := w.cache.Get(fmt.Sprintf("%d", id))
		if ok {
			start := t.(time.Time)
			d := float64(time.Since(start)) / float64(time.Millisecond)
			w.statsd.Histogram("dns.reply.time", d, tags, 1)
		} else {
			debug("%d not in cache", id)
		}

		for _, q := range dnsPacket.Questions {
			w.statsd.Count("dns.reply.question", 1, append(tags, []string{
				fmt.Sprintf("query:%s", string(q.Name)),
				fmt.Sprintf("query_type:%s", string(q.Name)),
			}...), 1)
		}

		for _, a := range dnsPacket.Answers {
			w.statsd.Count("dns.answer", 1, append(tags, []string{
				fmt.Sprintf("query:%s", string(a.Name)),
				fmt.Sprintf("query_type:%s", query_type(a.Type)),
			}...), 1)
		}
	} else {
		w.cache.Set(fmt.Sprintf("%d", id), time.Now(), cache.DefaultExpiration)

		// This is a query
		tags := []string{
			fmt.Sprintf("op_code:%s", op_code(dnsPacket.OpCode)),
		}
		w.statsd.Count("dns.query", 1, tags, 1)

		for _, q := range dnsPacket.Questions {
			w.statsd.Count("dns.question", 1, append(tags, []string{
				fmt.Sprintf("query:%s", string(q.Name)),
				fmt.Sprintf("query_type:%s", query_type(q.Type)),
			}...), 1)
		}
	}

	return nil
}

func query_type(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeMD:
		return "MD"
	case layers.DNSTypeMF:
		return "MF"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeMB:
		return "MB"
	case layers.DNSTypeMG:
		return "MG"
	case layers.DNSTypeMR:
		return "MR"
	case layers.DNSTypeNULL:
		return "NULL"
	case layers.DNSTypeWKS:
		return "WKS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeHINFO:
		return "HINFO"
	case layers.DNSTypeMINFO:
		return "MINFO"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return "UNKNOWN"
	}
}

func response_code(c layers.DNSResponseCode) string {
	switch c {
	case layers.DNSResponseCodeFormErr:
		return "FormErr"
	case layers.DNSResponseCodeServFail:
		return "ServFail"
	case layers.DNSResponseCodeNXDomain:
		return "NXDomain"
	case layers.DNSResponseCodeNotImp:
		return "NotImp"
	case layers.DNSResponseCodeRefused:
		return "Refused"
	case layers.DNSResponseCodeYXDomain:
		return "YXDomain"
	case layers.DNSResponseCodeYXRRSet:
		return "YXRRSet"
	case layers.DNSResponseCodeNXRRSet:
		return "NXRRSet"
	case layers.DNSResponseCodeNotAuth:
		return "NotAuth"
	case layers.DNSResponseCodeNotZone:
		return "NotZone"
	case layers.DNSResponseCodeBadVers:
		return "BadVers"
	case layers.DNSResponseCodeBadKey:
		return "BadKey"
	case layers.DNSResponseCodeBadTime:
		return "BadTime"
	case layers.DNSResponseCodeBadMode:
		return "BadMode"
	case layers.DNSResponseCodeBadName:
		return "BadName"
	case layers.DNSResponseCodeBadAlg:
		return "BadAlg"
	case layers.DNSResponseCodeBadTruc:
		return "BadTruc"
	default:
		return "OK"
	}
}

func op_code(t layers.DNSOpCode) string {
	switch t {
	case layers.DNSOpCodeQuery:
		return "Query"
	case layers.DNSOpCodeIQuery:
		return "IQuery"
	case layers.DNSOpCodeStatus:
		return "Status"
	case layers.DNSOpCodeNotify:
		return "Notify"
	case layers.DNSOpCodeUpdate:
		return "Update"
	default:
		return "UNKNOWN"
	}
	return ""
}

func debug(format string, args ...interface{}) (int, error) {
	return fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...)
}
