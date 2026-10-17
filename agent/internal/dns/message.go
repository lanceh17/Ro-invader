// Package dns implements the authoritative resolver that is the heart of both
// containment and identity.
//
// Two properties make DNS load-bearing here, and they are the same mechanism:
//
//   - Identity. In passive-only mode there is no other guaranteed source. A
//     device that resolves through us is enumerated; a device that does not is
//     invisible. Every query is therefore a chance to attribute activity.
//   - Containment. A quarantined device resolves only walled-garden domains
//     through us. Its restriction and its notification are the same event: it
//     asks for a name, and we answer with the remediation page.
//
// The message codec here is hand-written rather than pulled from
// golang.org/x/net/dns/dnsmessage. That is a deliberate trade, not an
// oversight: this project's CI gate bans golang.org/x/net from go.mod to keep
// the dependency surface (and specifically the raw-socket packages) out of the
// binary. A focused codec that parses only what the resolver needs — the
// header and the question section — is small enough to audit in one sitting,
// which for a component that parses attacker-controlled input from the LAN is
// worth more than a general-purpose library.
//
// It parses untrusted bytes on every call. The guards that matter are
// compression-pointer loop detection, bounded name length, and strict bounds
// checks; each is exercised by malformed-input tests.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// HeaderLen is the fixed size of a DNS message header in bytes.
const HeaderLen = 12

// Maximum lengths enforced against untrusted input.
const (
	// maxNameLen bounds a decoded domain name per RFC 1035. A longer name is
	// malformed; accepting one would let a peer exhaust memory.
	maxNameLen = 255
	// maxLabels bounds the label count, which together with maxNameLen stops
	// a decompression bomb from expanding into an enormous string.
	maxLabels = 128
	// maxJumps bounds compression-pointer hops. Legal messages use very few;
	// a large count means a cycle or a chain crafted to burn CPU.
	maxJumps = 32
	// maxQuestions bounds the question section we will parse. A resolver only
	// ever needs the first question; a peer sending thousands is not behaving
	// legitimately.
	maxQuestions = 4
)

// DNS record types and classes this resolver understands.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	ClassIN   uint16 = 1
)

// Response codes.
const (
	RCodeNoError uint8 = 0
	RCodeFormErr uint8 = 1
	RCodeNameErr uint8 = 3 // NXDOMAIN
	RCodeNotImp  uint8 = 4
	RCodeRefused uint8 = 5
)

// Flag bits in the header's second 16-bit word.
const (
	flagQR uint16 = 1 << 15
	flagAA uint16 = 1 << 10
	flagTC uint16 = 1 << 9
	flagRD uint16 = 1 << 8
)

// opcodeMask isolates the 4-bit opcode field.
const opcodeMask uint16 = 0x7800

// Question is one entry in the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Msg is a decoded DNS message. Only the header and question section are
// decoded; the answer, authority, and additional sections are carried as raw
// bytes so a forwarded response can be relayed verbatim without re-encoding.
type Msg struct {
	ID        uint16
	QR        bool
	Opcode    uint8
	AA        bool
	TC        bool
	RD        bool
	RCode     uint8
	Questions []Question

	// raw is the complete original message, retained so that a forwarded
	// response can be patched in place (only the ID and flags change) and
	// relayed without re-serializing every record.
	raw []byte
}

// Errors returned when parsing untrusted input. They are distinct so that the
// caller can distinguish "malformed" from "well-formed but unsupported",
// which matters for choosing the right response code.
var (
	ErrTruncated     = errors.New("dns: message truncated")
	ErrNameTooLong   = errors.New("dns: name exceeds 255 bytes")
	ErrTooManyLabels = errors.New("dns: too many labels")
	ErrPointerLoop   = errors.New("dns: compression pointer loop")
	ErrBadPointer    = errors.New("dns: compression pointer out of bounds")
	ErrReservedBits  = errors.New("dns: reserved label bits set")
	ErrTooManyRr     = errors.New("dns: too many records")
	ErrNotQuery      = errors.New("dns: message is not a query")
)

// ParseQuery decodes an incoming DNS query.
//
// It is strict on purpose. A message that is truncated, cyclic, over-long, or
// a response rather than a query is rejected outright; the caller answers with
// FORMERR rather than attempting to interpret bytes it cannot trust.
func ParseQuery(b []byte) (Msg, error) {
	var m Msg
	if len(b) < HeaderLen {
		return m, ErrTruncated
	}

	m.ID = binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	qdCount := binary.BigEndian.Uint16(b[4:6])

	m.QR = flags&flagQR != 0
	m.Opcode = uint8((flags & opcodeMask) >> 11)
	m.AA = flags&flagAA != 0
	m.TC = flags&flagTC != 0
	m.RD = flags&flagRD != 0
	m.RCode = uint8(flags & 0x000F)

	if m.QR {
		// A response arriving at a resolver is either a spoofed reply or a
		// misconfiguration. Either way it is not a query and must not be
		// answered as one.
		return m, ErrNotQuery
	}
	if m.Opcode != 0 {
		// Only standard queries are supported. Inverse and status queries
		// are obsolete and answering them invites abuse.
		return m, ErrNotQuery
	}
	if int(qdCount) > maxQuestions {
		return m, ErrTooManyRr
	}

	m.raw = b
	offset := HeaderLen
	for i := 0; i < int(qdCount); i++ {
		name, next, err := decodeName(b, offset)
		if err != nil {
			return m, err
		}
		offset = next
		if offset+4 > len(b) {
			return m, ErrTruncated
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[offset : offset+2]),
			Class: binary.BigEndian.Uint16(b[offset+2 : offset+4]),
		})
		offset += 4
	}
	return m, nil
}

// FirstQuestion returns the question the resolver acts on, and false when the
// message carried none. A resolver only ever answers the first question; the
// rest are ignored rather than rejected, because a query with trailing
// questions is unusual but not malicious.
func (m Msg) FirstQuestion() (Question, bool) {
	if len(m.Questions) == 0 {
		return Question{}, false
	}
	return m.Questions[0], true
}

// decodeName reads a possibly-compressed domain name starting at offset.
//
// The returned second value is the offset the caller should resume from,
// which is the position after the first compression pointer (or after the
// terminating zero) rather than after the last byte consumed. That distinction
// is the classic source of DNS parser bugs: a pointer can jump anywhere, so
// "where I finished reading" and "where the next field starts" are different.
//
// Three guards stop crafted input from exploiting this: a visited-offset set
// and a jump cap kill pointer cycles, and the label and name-length caps stop
// a decompression bomb from expanding without bound.
func decodeName(b []byte, offset int) (string, int, error) {
	var (
		labels     []string
		nameLen    int
		jumps      int
		nextOffset = -1
		visited    = make(map[int]struct{}, 4)
		pos        = offset
	)

	for {
		if pos >= len(b) {
			return "", 0, ErrTruncated
		}
		if _, seen := visited[pos]; seen {
			return "", 0, ErrPointerLoop
		}
		visited[pos] = struct{}{}

		length := int(b[pos])
		switch {
		case length == 0:
			// Root label terminates the name.
			pos++
			if nextOffset == -1 {
				nextOffset = pos
			}
			return strings.Join(labels, "."), nextOffset, nil

		case length&0xC0 == 0xC0:
			// Compression pointer: the low 14 bits are an absolute offset
			// into the message.
			if pos+1 >= len(b) {
				return "", 0, ErrTruncated
			}
			ptr := int(b[pos]&0x3F)<<8 | int(b[pos+1])
			if ptr >= len(b) {
				return "", 0, ErrBadPointer
			}
			if nextOffset == -1 {
				// The caller resumes after the pointer, not where the
				// pointer leads.
				nextOffset = pos + 2
			}
			pos = ptr
			jumps++
			if jumps > maxJumps {
				return "", 0, ErrPointerLoop
			}

		case length&0xC0 != 0:
			// 0x40 and 0x80 are reserved (extended labels). Rejecting them
			// avoids implementing semantics nobody uses and attackers probe
			// for.
			return "", 0, ErrReservedBits

		default:
			// Ordinary label.
			pos++
			if pos+length > len(b) {
				return "", 0, ErrTruncated
			}
			nameLen += length + 1 // +1 for the separating dot
			if nameLen > maxNameLen {
				return "", 0, ErrNameTooLong
			}
			if len(labels) >= maxLabels {
				return "", 0, ErrTooManyLabels
			}
			labels = append(labels, string(b[pos:pos+length]))
			pos += length
		}
	}
}

// encodeName serializes a domain name in uncompressed wire form.
//
// No compression is emitted. Compression exists to shrink responses, and every
// response this resolver builds is a single small record; the complexity of a
// compression offset table is not worth saving a dozen bytes. Input is
// validated so that a malformed configured name cannot produce an unparseable
// response.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name)+2 > maxNameLen { // +2 for length octets and root
		return nil, ErrNameTooLong
	}

	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			// An empty label ("a..b") is malformed rather than a wildcard.
			return nil, fmt.Errorf("dns: empty label in %q", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("dns: label %q exceeds 63 bytes", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// Answer is one resource record in a response this resolver constructs.
type Answer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	// Addr is set for A and AAAA records.
	Addr netip.Addr
}

// BuildResponse assembles a response to query q.
//
// The question section is echoed verbatim, which is what makes a response
// match its query in the eyes of a stub resolver. The transaction ID and the
// RD bit are copied from the query; the QR bit is set and RA is set to advertise
// recursion, which is what a forwarding resolver provides.
func BuildResponse(q Msg, rcode uint8, answers []Answer) ([]byte, error) {
	if len(q.Questions) == 0 {
		return nil, errors.New("dns: cannot respond to a query with no question")
	}

	// Header.
	out := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(out[0:2], q.ID)

	var flags uint16
	flags |= flagQR // this is a response
	flags |= flagAA // we answer authoritatively for what we answer
	if q.RD {
		flags |= flagRD // echo the recursion-desired bit
	}
	// RA (recursion available) is bit 7 of the low byte.
	flags |= 1 << 7
	flags |= uint16(rcode) & 0x000F
	binary.BigEndian.PutUint16(out[2:4], flags)

	// Only the first question is echoed; a query with trailing questions is
	// answered for its first, which is the only one a stub resolver acts on.
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], uint16(len(answers)))

	// Question section.
	qname, err := encodeName(q.Questions[0].Name)
	if err != nil {
		return nil, err
	}
	out = append(out, qname...)
	out = binary.BigEndian.AppendUint16(out, q.Questions[0].Type)
	out = binary.BigEndian.AppendUint16(out, q.Questions[0].Class)

	// Answer section.
	for _, a := range answers {
		rname, err := encodeName(a.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, rname...)
		out = binary.BigEndian.AppendUint16(out, a.Type)
		out = binary.BigEndian.AppendUint16(out, a.Class)
		out = binary.BigEndian.AppendUint32(out, a.TTL)

		var rdata []byte
		switch a.Type {
		case TypeA:
			if !a.Addr.Is4() {
				return nil, fmt.Errorf("dns: A record requires an IPv4 address, got %v", a.Addr)
			}
			ip := a.Addr.As4()
			rdata = ip[:]
		case TypeAAAA:
			if !a.Addr.Is6() {
				return nil, fmt.Errorf("dns: AAAA record requires an IPv6 address, got %v", a.Addr)
			}
			ip := a.Addr.As16()
			rdata = ip[:]
		default:
			return nil, fmt.Errorf("dns: unsupported answer type %d", a.Type)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
	}

	return out, nil
}

// BuildSinkhole builds a response answering q with the portal address.
//
// This is the walled-garden's enforcement point and its notification point at
// once: a quarantined device asks for an arbitrary name and receives the
// remediation page's address. Only A and AAAA questions are answered this way;
// other types get NOERROR with no answers, which tells the device the name
// exists but has no record of that type, rather than NXDOMAIN, which would
// look like a broken domain and send it retrying.
func BuildSinkhole(q Msg, portal netip.Addr) ([]byte, error) {
	question, ok := q.FirstQuestion()
	if !ok {
		return nil, errors.New("dns: cannot sinkhole a query with no question")
	}

	switch question.Type {
	case TypeA:
		if !portal.Is4() {
			// The device asked for A; answering with nothing is more honest
			// than synthesizing an IPv4 from an IPv6 portal.
			return BuildResponse(q, RCodeNoError, nil)
		}
		return BuildResponse(q, RCodeNoError, []Answer{{
			Name: question.Name, Type: TypeA, Class: ClassIN, TTL: 60, Addr: portal,
		}})
	case TypeAAAA:
		if !portal.Is6() {
			return BuildResponse(q, RCodeNoError, nil)
		}
		return BuildResponse(q, RCodeNoError, []Answer{{
			Name: question.Name, Type: TypeAAAA, Class: ClassIN, TTL: 60, Addr: portal,
		}})
	default:
		// No record of this type. NOERROR/ancount=0 is the correct refusal:
		// the name is handled, but we will not fabricate a record type we do
		// not have.
		return BuildResponse(q, RCodeNoError, nil)
	}
}

// BuildNXDomain refuses a name that does not exist.
func BuildNXDomain(q Msg) ([]byte, error) {
	return BuildResponse(q, RCodeNameErr, nil)
}

// BuildRefused declines to answer, which is what a resolver does when policy
// forbids the query outright (for example, a malformed name from a peer that
// is not going to be helped by a fabricated answer).
func BuildRefused(q Msg) ([]byte, error) {
	return BuildResponse(q, RCodeRefused, nil)
}

// BuildFormErr answers a message that could not be parsed. When the header
// itself is intact enough to read the ID, that ID is echoed so the stub can
// match the reply; otherwise a zero ID is used.
func BuildFormErr(raw []byte) []byte {
	var id uint16
	if len(raw) >= 2 {
		id = binary.BigEndian.Uint16(raw[0:2])
	}
	out := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(out[0:2], id)
	// QR=1, RCODE=FORMERR, RA=1.
	binary.BigEndian.PutUint16(out[2:4], flagQR|(1<<7)|uint16(RCodeFormErr))
	return out
}

// PatchRelay rewrites a forwarded upstream response so that it matches the
// original client's query.
//
// The upstream replies with the ID it saw, which we set to the client's, and
// with its own RD bit. Everything else — the answer, authority, and additional
// sections — is relayed byte-for-byte, which is why Msg keeps the raw message:
// re-encoding every record type would mean implementing all of them, and
// getting one subtly wrong breaks resolution for that type in ways that are
// hard to notice.
func PatchRelay(upstream []byte, clientID uint16, clientRD bool) []byte {
	if len(upstream) < HeaderLen {
		return nil
	}
	out := make([]byte, len(upstream))
	copy(out, upstream)

	binary.BigEndian.PutUint16(out[0:2], clientID)

	flags := binary.BigEndian.Uint16(out[2:4])
	if clientRD {
		flags |= flagRD
	} else {
		flags &^= flagRD
	}
	// Guarantee the QR bit is set; a relayed message is always a response.
	flags |= flagQR
	binary.BigEndian.PutUint16(out[2:4], flags)

	return out
}
