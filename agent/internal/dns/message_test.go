package dns

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// buildQuery assembles a minimal, valid DNS query for name/type. It is the
// fixture every parse test starts from, and it doubles as the encoder's
// round-trip check.
func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	qname, err := encodeName(name)
	if err != nil {
		t.Fatalf("encodeName(%q): %v", name, err)
	}
	out := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(out[0:2], 0x1234) // a fixed ID
	binary.BigEndian.PutUint16(out[2:4], flagRD) // recursion desired
	binary.BigEndian.PutUint16(out[4:6], 1)      // one question
	out = append(out, qname...)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, ClassIN)
	return out
}

func TestParseSimpleQuery(t *testing.T) {
	raw := buildQuery(t, "cdn-lfs.huggingface.co", TypeA)

	m, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if m.ID != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234", m.ID)
	}
	if !m.RD {
		t.Error("RD bit not preserved")
	}
	if m.QR {
		t.Error("QR should be false on a query")
	}

	q, ok := m.FirstQuestion()
	if !ok {
		t.Fatal("FirstQuestion returned false")
	}
	if q.Name != "cdn-lfs.huggingface.co" {
		t.Errorf("Name = %q, want cdn-lfs.huggingface.co", q.Name)
	}
	if q.Type != TypeA {
		t.Errorf("Type = %d, want %d", q.Type, TypeA)
	}
	if q.Class != ClassIN {
		t.Errorf("Class = %d, want %d", q.Class, ClassIN)
	}
}

func TestParseRootQuery(t *testing.T) {
	// A root query (the DNS "priming" query) has an empty name. It must parse
	// rather than error, or the resolver fails the one query every stub sends
	// at startup.
	raw := buildQuery(t, "", TypeA)
	m, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	q, _ := m.FirstQuestion()
	if q.Name != "" {
		t.Errorf("Name = %q, want empty", q.Name)
	}
}

func TestParseLongestLegalName(t *testing.T) {
	// Three 63-byte labels plus a shorter one stays under the 255-byte
	// ceiling (nameLen counts each label's length octet). Four 63-byte labels
	// would be 256 and is correctly rejected, which is a separate case.
	label := strings.Repeat("a", 63)
	name := label + "." + label + "." + label + "." + strings.Repeat("b", 60)
	raw := buildQuery(t, name, TypeA)
	m, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("a legal long name must parse: %v", err)
	}
	q, _ := m.FirstQuestion()
	if q.Name != name {
		t.Errorf("Name = %q, want the full name round-tripped", q.Name)
	}
}

// TestFourMaxLabelsRejected pins the boundary: four 63-byte labels encode to
// 256 octets counting their length bytes, which is one over the RFC 1035
// ceiling. The bytes are built by hand because encodeName would refuse to
// produce them; this test is about the parser's own limit.
func TestFourMaxLabelsRejected(t *testing.T) {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	for i := 0; i < 4; i++ {
		raw = append(raw, 63)
		raw = append(raw, strings.Repeat("a", 63)...)
	}
	raw = append(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, TypeA)
	raw = binary.BigEndian.AppendUint16(raw, ClassIN)

	if _, err := ParseQuery(raw); err != ErrNameTooLong {
		t.Errorf("err = %v, want ErrNameTooLong", err)
	}
}

// TestCompressionPointerResolves follows a pointer to a name stored earlier in
// the message, which is how real resolvers and stubs compress repeated names.
func TestCompressionPointerResolves(t *testing.T) {
	// Layout: header | "example.com" (at offset 12) | question with a pointer.
	base := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(base[4:6], 1)

	// Store "example.com" at offset 12.
	example, _ := encodeName("example.com")
	nameOffset := len(base)
	base = append(base, example...)

	// Question: name is a pointer to nameOffset, then type/class.
	base = append(base, 0xC0, byte(nameOffset)) // pointer
	base = binary.BigEndian.AppendUint16(base, TypeA)
	base = binary.BigEndian.AppendUint16(base, ClassIN)

	m, err := ParseQuery(base)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	q, _ := m.FirstQuestion()
	if q.Name != "example.com" {
		t.Errorf("Name = %q, want example.com (pointer resolved)", q.Name)
	}
}

// TestPointerLoopRejected is the guard that stops a crafted message from
// sending the parser around a cycle forever.
func TestPointerLoopRejected(t *testing.T) {
	// Two pointers that reference each other.
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	// Pointer at offset 12 -> 14; pointer at 14 -> 12.
	raw = append(raw, 0xC0, 14)
	raw = append(raw, 0xC0, 12)

	if _, err := ParseQuery(raw); err != ErrPointerLoop {
		t.Errorf("err = %v, want ErrPointerLoop", err)
	}
}

// TestSelfPointerRejected covers the degenerate one-element cycle.
func TestSelfPointerRejected(t *testing.T) {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 0xC0, 12) // points at itself

	if _, err := ParseQuery(raw); err != ErrPointerLoop {
		t.Errorf("err = %v, want ErrPointerLoop", err)
	}
}

// TestJumpCapRejected covers a long pointer chain that only closes into a
// cycle after more hops than the cap allows. The visited-offset set cannot
// catch it (no offset repeats until the cycle completes), so the jump cap is
// the guard that fires. Without it, a crafted chain would burn CPU linear in
// its length.
func TestJumpCapRejected(t *testing.T) {
	// n pointers, each leading to the next, the last closing the loop back to
	// the first. n exceeds maxJumps, so the cap trips before the cycle does.
	n := maxJumps + 4
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	for i := 0; i < n; i++ {
		target := HeaderLen + 2*(i+1)
		if i == n-1 {
			target = HeaderLen // close the cycle
		}
		raw = append(raw, 0xC0, byte(target))
	}

	if _, err := ParseQuery(raw); err != ErrPointerLoop {
		t.Errorf("err = %v, want ErrPointerLoop from the jump cap", err)
	}
}

func TestOutOfBoundsPointerRejected(t *testing.T) {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 0xC0, 0xFF) // 0xFF is past any message we would send

	if _, err := ParseQuery(raw); err != ErrBadPointer {
		t.Errorf("err = %v, want ErrBadPointer", err)
	}
}

func TestReservedLabelBitsRejected(t *testing.T) {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 0x80, 0x01) // 0x80 is a reserved label type

	if _, err := ParseQuery(raw); err != ErrReservedBits {
		t.Errorf("err = %v, want ErrReservedBits", err)
	}
}

func TestNameTooLongRejected(t *testing.T) {
	// A single label that would push the decoded name past 255 bytes.
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 63)
	raw = append(raw, strings.Repeat("a", 63)...)
	// Repeat enough labels to exceed the name ceiling.
	for i := 0; i < 5; i++ {
		raw = append(raw, 63)
		raw = append(raw, strings.Repeat("b", 63)...)
	}
	raw = append(raw, 0)

	if _, err := ParseQuery(raw); err != ErrNameTooLong {
		t.Errorf("err = %v, want ErrNameTooLong", err)
	}
}

func TestTruncatedMessageRejected(t *testing.T) {
	if _, err := ParseQuery([]byte{0x12}); err != ErrTruncated {
		t.Errorf("short header: err = %v, want ErrTruncated", err)
	}

	// Header claims a question but none follows.
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	if _, err := ParseQuery(raw); err != ErrTruncated {
		t.Errorf("missing question: err = %v, want ErrTruncated", err)
	}
}

// TestResponseRejected: a resolver must not answer a response, or an attacker
// can drive it into replying to its own replies.
func TestResponseRejected(t *testing.T) {
	raw := buildQuery(t, "example.com", TypeA)
	binary.BigEndian.PutUint16(raw[2:4], flagQR|flagRD)

	if _, err := ParseQuery(raw); err != ErrNotQuery {
		t.Errorf("err = %v, want ErrNotQuery", err)
	}
}

func TestNonStandardOpcodeRejected(t *testing.T) {
	raw := buildQuery(t, "example.com", TypeA)
	// Opcode 1 = inverse query.
	flags := binary.BigEndian.Uint16(raw[2:4])
	flags |= 1 << 11
	binary.BigEndian.PutUint16(raw[2:4], flags)

	if _, err := ParseQuery(raw); err != ErrNotQuery {
		t.Errorf("err = %v, want ErrNotQuery for a non-standard opcode", err)
	}
}

func TestTooManyQuestionsRejected(t *testing.T) {
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(raw[4:6], maxQuestions+1)
	if _, err := ParseQuery(raw); err != ErrTooManyRr {
		t.Errorf("err = %v, want ErrTooManyRr", err)
	}
}

func TestEncodeNameRejectsEmptyLabel(t *testing.T) {
	if _, err := encodeName("a..b"); err == nil {
		t.Error("an empty label must be rejected, not treated as a wildcard")
	}
}

func TestEncodeNameRejectsLongLabel(t *testing.T) {
	if _, err := encodeName(strings.Repeat("a", 64)); err == nil {
		t.Error("a label over 63 bytes must be rejected")
	}
}

func TestEncodeNameLowercases(t *testing.T) {
	out, err := encodeName("Example.COM")
	if err != nil {
		t.Fatalf("encodeName: %v", err)
	}
	name, _, err := decodeName(out, 0)
	if err != nil {
		t.Fatalf("decodeName: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want lowercased example.com", name)
	}
}

func TestBuildSinkholeA(t *testing.T) {
	raw := buildQuery(t, "blocked.example", TypeA)
	q, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	portal := netip.MustParseAddr("192.168.1.1")
	resp, err := BuildSinkhole(q, portal)
	if err != nil {
		t.Fatalf("BuildSinkhole: %v", err)
	}

	r, err := ParseQuery(resp)
	if err == nil && !r.QR {
		t.Error("a sinkhole response must have QR set")
	}
	if len(resp) <= HeaderLen {
		t.Fatal("sinkhole response has no answer")
	}
	// The answer's rdata must be the portal's four bytes.
	rdata := resp[len(resp)-4:]
	if netip.AddrFrom4([4]byte{rdata[0], rdata[1], rdata[2], rdata[3]}) != portal {
		t.Errorf("rdata = %v, want portal %v", rdata, portal)
	}
}

// TestBuildSinkholeTypeMismatch: answering an AAAA question with an IPv4 portal
// (or vice versa) must not fabricate a record. NOERROR with no answers is the
// honest refusal.
func TestBuildSinkholeTypeMismatch(t *testing.T) {
	raw := buildQuery(t, "blocked.example", TypeAAAA)
	q, _ := ParseQuery(raw)

	resp, err := BuildSinkhole(q, netip.MustParseAddr("192.168.1.1"))
	if err != nil {
		t.Fatalf("BuildSinkhole: %v", err)
	}
	// ANCOUNT is bytes 6-8.
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 when the portal type does not match", ancount)
	}
}

// TestBuildSinkholeOtherType: a TXT question must not receive a synthesized A
// record.
func TestBuildSinkholeOtherType(t *testing.T) {
	raw := buildQuery(t, "blocked.example", TypeTXT)
	q, _ := ParseQuery(raw)

	resp, err := BuildSinkhole(q, netip.MustParseAddr("192.168.1.1"))
	if err != nil {
		t.Fatalf("BuildSinkhole: %v", err)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 for a non-address question", ancount)
	}
}

func TestBuildNXDomainSetsRCode(t *testing.T) {
	raw := buildQuery(t, "nope.example", TypeA)
	q, _ := ParseQuery(raw)

	resp, err := BuildNXDomain(q)
	if err != nil {
		t.Fatalf("BuildNXDomain: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if rcode := uint8(flags & 0x000F); rcode != RCodeNameErr {
		t.Errorf("RCODE = %d, want %d (NXDOMAIN)", rcode, RCodeNameErr)
	}
	if flags&flagQR == 0 {
		t.Error("QR bit must be set")
	}
}

// TestPatchRelayPreservesPayload is the property that makes forwarding safe:
// the answer section must survive verbatim, because re-encoding every record
// type would mean implementing all of them.
func TestPatchRelayPreservesPayload(t *testing.T) {
	// A fabricated upstream response with a distinctive payload.
	upstream := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(upstream[0:2], 0xABCD) // upstream's ID
	binary.BigEndian.PutUint16(upstream[4:6], 1)
	binary.BigEndian.PutUint16(upstream[6:8], 1) // one answer
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	upstream = append(upstream, payload...)

	out := PatchRelay(upstream, 0x1234, true)
	if got := binary.BigEndian.Uint16(out[0:2]); got != 0x1234 {
		t.Errorf("ID = %#x, want the client's 0x1234", got)
	}
	flags := binary.BigEndian.Uint16(out[2:4])
	if flags&flagQR == 0 {
		t.Error("QR must be set on a relayed response")
	}
	if flags&flagRD == 0 {
		t.Error("the client's RD bit must be preserved")
	}
	// Everything after the header must be byte-identical.
	if string(out[HeaderLen:]) != string(payload) {
		t.Errorf("payload altered: %v", out[HeaderLen:])
	}
}

func TestPatchRelayShortMessageReturnsNil(t *testing.T) {
	if got := PatchRelay([]byte{0x00, 0x01}, 0, false); got != nil {
		t.Errorf("PatchRelay on a short message = %v, want nil", got)
	}
}

// TestBuildFormErrEchoesID: a stub that gets a FORMERR back needs to match it
// to its query, so the ID must survive even when nothing else parses.
func TestBuildFormErrEchoesID(t *testing.T) {
	raw := []byte{0x12, 0x34, 0xFF, 0xFF}
	resp := BuildFormErr(raw)
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234 echoed", got)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if rcode := uint8(flags & 0x000F); rcode != RCodeFormErr {
		t.Errorf("RCODE = %d, want FORMERR", rcode)
	}
}

// TestNoCompressionInEncodedName documents a deliberate simplicity choice: the
// encoder never emits pointers, so a decoded response never needs the offset
// table that makes compression parsers hard.
func TestNoCompressionInEncodedName(t *testing.T) {
	out, err := encodeName("a.example.com")
	if err != nil {
		t.Fatalf("encodeName: %v", err)
	}
	for _, b := range out {
		if b&0xC0 == 0xC0 {
			t.Fatal("encodeName emitted a compression pointer; it must not")
		}
	}
}
