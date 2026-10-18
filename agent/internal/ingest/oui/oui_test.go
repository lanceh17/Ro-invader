package oui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fixtureOUIs is a verbatim excerpt of the real MA-L listing, in its real
// shape: the three-line header, CRLF endings, the fixed-width gap between the
// prefix column and the organization column, and the address block that
// follows each assignment. The organizations are real registrations.
//
// It is a const string rather than a file on disk so a reader can see the whole
// wire format in one place, and so no fixture can drift out of the repository
// the way a binary blob eventually does. The two entries the rest of the
// codebase already names -- Hikvision and Raspberry Pi -- are here because
// those are the OUIs its own tests reference.
const fixtureOUIs = "OUI/MA-L                                                    Organization                                 \r\n" +
	"company_id                                                  Organization                                 \r\n" +
	"                                                            Address                                      \r\n" +
	"                                                                                                          \r\n" +
	"28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\r\n" +
	"286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.\r\n" +
	"\t\t\t\tNo.388 Ning Qiao Road,Jin Qiao Pudong Shanghai\r\n" +
	"\t\t\t\tShanghai     201206\r\n" +
	"\t\t\t\tCN\r\n" +
	"                                                                                                          \r\n" +
	"0C-75-D2   (hex)\t\tHangzhou Hikvision Digital Technology Co.,Ltd.\r\n" +
	"0C75D2     (base 16)\t\tHangzhou Hikvision Digital Technology Co.,Ltd.\r\n" +
	"\t\t\t\tNo.1888 HuaMu Road,Hi-tech Park\r\n" +
	"\t\t\t\tHangzhou    310051\r\n" +
	"\t\t\t\tCN\r\n" +
	"                                                                                                          \r\n" +
	"D8-3A-DD   (hex)\t\tRaspberry Pi Trading Ltd\r\n" +
	"D83ADD     (base 16)\t\tRaspberry Pi Trading Ltd\r\n" +
	"\t\t\t\tRaspberry Pi Trading Ltd\r\n" +
	"\t\t\t\tUK\r\n" +
	"                                                                                                          \r\n" +
	"E8-0A-B9   (hex)\t\tCisco Systems, Inc\r\n" +
	"E80AB9     (base 16)\t\tCisco Systems, Inc\r\n" +
	"\t\t\t\t80 West Tasman Drive\r\n" +
	"\t\t\t\tSan Jose  CA  94568\r\n" +
	"\t\t\t\tUS\r\n" +
	"                                                                                                          \r\n" +
	"90-56-07   (hex)\t\tSichuan\u00a0AI-Link\u00a0Technology\u00a0Co.,\u00a0Ltd.\r\n" +
	"905607     (base 16)\t\tSichuan\u00a0AI-Link\u00a0Technology\u00a0Co.,\u00a0Ltd.\r\n" +
	"\t\t\t\tCN\r\n" +
	"                                                                                                          \r\n" +
	"00-50-79   (hex)\t\tPrivate\r\n"

// malformedOUIs mixes the fixture's real records with every shape of line a
// regenerated listing or a hostile endpoint can present. The valid entries
// must survive all of it: a bad line costs the one row it names, never the
// table it was sitting in.
const malformedOUIs = "" +
	"28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\r\n" +
	"ZZ-ZZ-ZZ   (hex)\t\tNot Hex At All\r\n" +
	"\r\n" +
	"   \r\n" +
	"\t\t\t\tjust an address line\r\n" +
	"00-00   (hex)\t\tToo Short\r\n" +
	"00-00-0-0   (hex)\t\tDash Inside A Byte\r\n" +
	"00-00-0C-0C   (hex)\t\tFour Bytes Is An MA-S\r\n" +
	"0013EC     (base 16)\t\tNot An Assignment, Just A Restatement\r\n" +
	"   0C-75-D2   (hex)\t\tJunk In Front Of The Prefix\r\n" +
	"0C-75-D2   (hex)\t\t\r\n" +
	"0C-75-D2   (hex)\t\tHangzhou Hikvision Digital Technology Co.,Ltd.\r\n" +
	"00-1C-42   (hex)\t\tParallels Virtual Machines\r\n" +
	"not a prefix at all\r\n" +
	"D8-3A-DD   (hex)     Raspberry Pi Trading Ltd\n" +
	"1-2-3-4-5-6-7 (hex)\tMA-M Width In An MA-L File\r\n"

// mustMAC parses a MAC the way a caller would, failing the test if the literal
// itself is wrong so a typo in a test case cannot masquerade as a lookup miss.
func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

// loadFixture returns a Store holding the excerpt, with no HTTP anywhere in
// the picture. It drives the same publish path Load uses, so a test cannot pass
// by calling something Load never calls.
func loadFixture(t *testing.T, raw string) *Store {
	t.Helper()
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.set([]byte(raw)); err != nil {
		t.Fatalf("set: %v", err)
	}
	return s
}

// TestLoadResolvesEveryFixtureEntry is the end-to-end case: the registry
// served over HTTP, loaded through the real path, and queried by a MAC.
func TestLoadResolvesEveryFixtureEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		_, _ = w.Write([]byte(fixtureOUIs))
	}))
	defer srv.Close()

	s, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d before Load, want an empty table", s.Len())
	}

	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Six, not twelve. Each record appears twice in the file -- once as
	// XX-XX-XX, once as the same prefix undashed in base 16 -- so a parser
	// that keyed on "a line starting with hex digits" would double every
	// assignment, and one that counted address and country lines would inflate
	// it further.
	if got, want := s.Len(), 6; got != want {
		t.Errorf("Len = %d, want %d: the base-16 restatements and address lines are not assignments", got, want)
	}

	tests := []struct {
		name string
		mac  string
		want string
	}{
		{"Hikvision camera", "0c:75:d2:11:22:33", "Hangzhou Hikvision Digital Technology Co.,Ltd."},
		{"Raspberry Pi", "d8:3a:dd:00:00:01", "Raspberry Pi Trading Ltd"},
		{"Cisco", "e8:0a:b9:ff:ff:ff", "Cisco Systems, Inc"},
		{"Nokia", "28:6f:b9:01:02:03", "Nokia Shanghai Bell Co., Ltd."},
		{"IEEE's own reserved block, named as published", "00:50:79:aa:bb:cc", "Private"},
		// U+00A0 no-break spaces, which is what the live file carries where a
		// name was typed with a full-width space. bytes.TrimSpace is
		// Unicode-aware, so a name that began with one would be trimmed; a
		// name carrying them internally must survive untouched.
		{"non-ASCII vendor name survives verbatim", "90:56:07:00:00:01", "Sichuan\u00a0AI-Link\u00a0Technology\u00a0Co.,\u00a0Ltd."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := s.Lookup(mustMAC(t, tt.mac))
			if !ok {
				t.Fatalf("Lookup(%s) found nothing", tt.mac)
			}
			if got != tt.want {
				t.Errorf("Lookup(%s) = %q, want %q", tt.mac, got, tt.want)
			}
		})
	}
}

// TestLookupMatchesOnByteBoundary is the rule that stops a substring search
// from becoming a false vendor. Matching must come from the leading three
// octets and nothing else: an address that happens to contain the same digits
// three bytes later belongs to whatever holds those.
func TestLookupMatchesOnByteBoundary(t *testing.T) {
	s := loadFixture(t, fixtureOUIs)

	if _, ok := s.Lookup(net.HardwareAddr{0x0c, 0x75, 0xd2}); !ok {
		t.Error("a bare three-byte OUI did not resolve; the table must key on the prefix itself")
	}
	if _, ok := s.Lookup(net.HardwareAddr{0x0c, 0x75, 0xd2, 0x11, 0x22, 0x33}); !ok {
		t.Error("a six-byte address did not resolve through its leading OUI")
	}
	// An address longer than six bytes resolves through the same three, which
	// is the point: an EUI-64 built from an MA-L assignment really is that
	// organization's hardware, and refusing it would be losing a true answer
	// to protect against a false one.
	if _, ok := s.Lookup(net.HardwareAddr{0x0c, 0x75, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x01}); !ok {
		t.Error("an eight-byte address did not resolve through its leading OUI")
	}

	// The same three hex digits, not at the front.
	if v, ok := s.Lookup(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x0c, 0x75, 0xd2}); ok {
		t.Errorf("Lookup matched an OUI sitting at bytes 3-5 of the address and returned %q", v)
	}
	// One byte off the front: the prefix is now bb:cc:0c.
	if v, ok := s.Lookup(net.HardwareAddr{0xbb, 0xcc, 0x0c, 0x11, 0x22, 0x33}); ok {
		t.Errorf("Lookup matched a shifted prefix and returned %q", v)
	}
}

// TestLookupRefusesAddressesItCannotAnswerFor covers the inputs where a
// match would be a fabrication. Each of these returns false rather than the
// nearest plausible answer, which is the trade router.Lease.Vendor already
// documents.
func TestLookupRefusesAddressesItCannotAnswerFor(t *testing.T) {
	s := loadFixture(t, fixtureOUIs)

	tests := []struct {
		name string
		mac  net.HardwareAddr
	}{
		{"nil", nil},
		{"empty", net.HardwareAddr{}},
		{"one byte", net.HardwareAddr{0x0c}},
		{"two bytes", net.HardwareAddr{0x0c, 0x75}},
		// Manufacturer bit set: the low bytes are the device maker's choice,
		// so any prefix they match is coincidence. This is what a randomized
		// Wi-Fi address looks like.
		{"locally administered", net.HardwareAddr{0x0e, 0x75, 0xd2, 0x11, 0x22, 0x33}},
		// A group address names a set of listeners, not a device.
		{"multicast", net.HardwareAddr{0x01, 0x00, 0x0c, 0x00, 0x00, 0x00}},
		{"broadcast", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"unlisted prefix", net.HardwareAddr{0xff, 0xff, 0xfe, 0x00, 0x00, 0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v, ok := s.Lookup(tt.mac); ok {
				t.Errorf("Lookup(%v) = (%q, true), want no answer: guessing a vendor is worse than none", tt.mac, v)
			}
		})
	}
}

// TestLookupIsCaseInsensitive pins the byte-level behavior. A MAC arrives from
// a router, a file, or a human in whichever spelling they favour, and every
// spelling of one address must resolve to the same organization.
func TestLookupIsCaseInsensitive(t *testing.T) {
	s := loadFixture(t, fixtureOUIs)

	spellings := []string{
		"0c:75:d2:11:22:33",
		"0C:75:D2:11:22:33",
		"0C:75:D2:aa:bb:cc",
		"0c-75-d2-11-22-33",
		"0C-75-D2-AA-BB-CC",
		"0c75d2112233",
	}
	var first string
	for i, sp := range spellings {
		v, ok := s.Lookup(mustMAC(t, sp))
		if !ok {
			t.Errorf("Lookup(%q) found nothing; every spelling of one address must resolve alike", sp)
			continue
		}
		if i == 0 {
			first = v
			continue
		}
		if v != first {
			t.Errorf("Lookup(%q) = %q, want %q", sp, v, first)
		}
	}

	// And the registry's own mixed-case organization names are preserved
	// rather than folded, because an operator's remediation map is keyed on
	// what IEEE published.
	if v, _ := s.Lookup(mustMAC(t, "0c:75:d2:00:00:01")); v != "Hangzhou Hikvision Digital Technology Co.,Ltd." {
		t.Errorf("mixed-case vendor was rewritten to %q", v)
	}
}

// TestParseSkipsBadLinesWithoutLosingTheTable is the load contract. The
// listing is regenerated daily by a batch job, so a malformed row is an
// expected condition rather than an exceptional one, and one bad row must not
// cost the other forty thousand.
func TestParseSkipsBadLinesWithoutLosingTheTable(t *testing.T) {
	s := loadFixture(t, malformedOUIs)

	// 28-6F-B9, 0C-75-D2, 00-1C-42 and D8-3A-DD are the only valid rows; the
	// D8-3A-DD one is the case a re-serialized listing arrives as, a lone LF
	// among CRLF neighbours.
	if got, want := s.Len(), 4; got != want {
		t.Errorf("Len = %d, want %d: exactly the four valid rows survive", got, want)
	}

	for _, tt := range []struct{ mac, want string }{
		{"28:6f:b9:00:00:01", "Nokia Shanghai Bell Co., Ltd."},
		{"0c:75:d2:00:00:01", "Hangzhou Hikvision Digital Technology Co.,Ltd."},
		{"00:1c:42:00:00:01", "Parallels Virtual Machines"},
		{"d8:3a:dd:00:00:01", "Raspberry Pi Trading Ltd"},
	} {
		got, ok := s.Lookup(mustMAC(t, tt.mac))
		if !ok {
			t.Errorf("Lookup(%s) found nothing, though its row was valid", tt.mac)
			continue
		}
		if got != tt.want {
			t.Errorf("Lookup(%s) = %q, want %q", tt.mac, got, tt.want)
		}
	}
}

// TestParsePrefixRefusesWrongWidthOrNonHex covers the one rule that keeps an
// MA-M or MA-S row out of an MA-L key. Seven- and nine-hex-digit prefixes live
// in different IEEE files; rounding one to the nearest 24 bits would name
// whoever holds the OUI that happens to contain it.
func TestParsePrefixRefusesWrongWidthOrNonHex(t *testing.T) {
	tests := []struct {
		in   string
		ok   bool
		want string // expected key on success
	}{
		{"00-00-0C", true, "00:00:0c"},
		{"28-6f-b9", true, "28:6f:b9"},
		{"286FB9", true, "28:6f:b9"},
		{"00000c", true, "00:00:0c"},
		{"FF-FF-FF", true, "ff:ff:ff"},
		{"", false, ""},
		{"00-00", false, ""},
		{"00", false, ""},
		{"0-0-0-C", false, ""},
		{"0C-75-D", false, ""},
		{"0C-75-D2-11", false, ""},
		{"0C-75-D2-11-22-33", false, ""},
		{"ZZ-ZZ-ZZ", false, ""},
		{"0C-75-DG", false, ""},
		{"0C 75 D2", false, ""},
		{"(hex)", false, ""},
		{"Cisco Systems", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			key, ok := parsePrefix([]byte(tt.in))
			if ok != tt.ok {
				t.Fatalf("parsePrefix(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if !ok {
				return
			}
			if got := net.HardwareAddr(key[:]).String(); got != tt.want {
				t.Errorf("parsePrefix(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseTakesFirstOfADuplicatedOUI makes the registry's own repeated rows
// deterministic. The live listing keeps historical assignments, and 08-00-30
// appears three times under three different organizations; which one a table
// reports must not depend on parse order.
func TestParseTakesFirstOfADuplicatedOUI(t *testing.T) {
	raw := "08-00-30   (hex)\t\tNETWORK RESEARCH CORPORATION\r\n" +
		"08-00-30   (hex)\t\tROYAL MELBOURNE INST OF TECH\r\n" +
		"08-00-30   (hex)\t\tCERN\r\n"

	s := loadFixture(t, raw)
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	v, _ := s.Lookup(mustMAC(t, "08:00:30:00:00:01"))
	if v != "NETWORK RESEARCH CORPORATION" {
		t.Errorf("duplicate OUI resolved to %q, want the first record in the file", v)
	}
}

// TestLoadAcceptsUnseparatedPrefixesAndBareLines covers the two forms a
// stripped or re-serialized listing arrives in. Real, every record is dashed
// and CRLF; the bare undashed form is what a base-16 restatement spells, and a
// file that has lost its line endings must still load rather than come back
// empty.
func TestLoadAcceptsUnseparatedPrefixesAndBareLines(t *testing.T) {
	raw := "00-00-0C   (hex)\tCisco Systems, Inc\n" +
		"0013EC     (hex)\tXerox Corporation\n"

	s := loadFixture(t, raw)
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if v, ok := s.Lookup(mustMAC(t, "00:00:0c:11:22:33")); !ok || v != "Cisco Systems, Inc" {
		t.Errorf("dashed prefix = (%q, %v), want Cisco Systems, Inc", v, ok)
	}
	if v, ok := s.Lookup(mustMAC(t, "00:13:ec:11:22:33")); !ok || v != "Xerox Corporation" {
		t.Errorf("undashed prefix = (%q, %v), want Xerox Corporation", v, ok)
	}
}

// TestLoadReportsHTTPFailures pins the error contract. Every failure an
// operator can hit has to arrive naming its cause, because a message that only
// says "oui" sends them looking for the wrong thing.
func TestLoadReportsHTTPFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []string
	}{
		{
			name:    "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusNotFound) },
			want:    []string{"404", "Not Found"},
		},
		{
			name:    "forbidden",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
			want:    []string{"403"},
		},
		{
			// A captive portal answering 200 is indistinguishable from a
			// good load by status alone. The only defence is refusing a table
			// that parsed to nothing, so a good table is not emptied by it.
			name: "error page behind a 200",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<html><body>Sign in</body></html>"))
			},
			want: []string{"no assignments"},
		},
		{
			name:    "empty body",
			handler: func(w http.ResponseWriter, _ *http.Request) {},
			want:    []string{"no assignments"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			s, err := New(Config{Endpoint: srv.URL})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = s.Load(context.Background())
			if err == nil {
				t.Fatal("Load must report the failure")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if !strings.Contains(err.Error(), "oui:") {
				t.Errorf("error %q is not prefixed with the package name", err)
			}
		})
	}
}

// TestLoadKeepsThePreviousTableOnFailure is the retention rule, and it is the
// one that matters. If a failed refresh emptied the table, every device's
// vendor would silently become unknown and the loss would look exactly like a
// network full of hardware IEEE has never heard of.
func TestLoadKeepsThePreviousTableOnFailure(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			http.Error(w, "gone", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(fixtureOUIs))
	}))
	defer srv.Close()

	s, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	before := s.Len()

	fail = true
	if err := s.Load(context.Background()); err == nil {
		t.Fatal("second Load must report the failure")
	}
	if s.Len() != before {
		t.Errorf("Len = %d after a failed refresh, want the %d retained", s.Len(), before)
	}
	if v, ok := s.Lookup(mustMAC(t, "0c:75:d2:11:22:33")); !ok || v != "Hangzhou Hikvision Digital Technology Co.,Ltd." {
		t.Errorf("vendor lookup after a failed refresh = (%q, %v), want the retained value", v, ok)
	}
}

// TestLoadRejectsOversizedResponse covers the read bound. A cap that silently
// truncated would parse the first megabytes of an endless stream into a table
// that looks complete and is missing its tail, which is the one failure mode a
// vendor table must not have.
func TestLoadRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Streamed with no declared length, which is how an endpoint that
		// never ends actually presents: chunked, forever.
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'x'
		}
		for written := 0; written < maxBody+(1<<20); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	s, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Load(context.Background())
	if err == nil {
		t.Fatal("Load must refuse a response past the cap")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error %q does not say the response exceeded the cap", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d after an oversized response, want the table left empty", s.Len())
	}
}

// TestNewValidatesEndpoint keeps a mistyped endpoint from surfacing later as
// an HTTP client complaining about a protocol scheme.
func TestNewValidatesEndpoint(t *testing.T) {
	for _, tt := range []struct{ name, endpoint, want string }{
		{"no scheme", "example.com/oui.txt", "http or https"},
		{"unsupported scheme", "ftp://example.com/oui.txt", "http or https"},
		{"unparseable", "http://[::1", "Endpoint"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{Endpoint: tt.endpoint})
			if err == nil {
				t.Fatalf("New(%q) must fail", tt.endpoint)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New with an empty Config: %v", err)
	}
	if s.cfg.Endpoint != DefaultEndpoint {
		t.Errorf("Endpoint = %q, want the public registry %q", s.cfg.Endpoint, DefaultEndpoint)
	}
	if s.cfg.HTTPTimeout != defaultHTTPTimeout {
		t.Errorf("HTTPTimeout = %v, want the %v default", s.cfg.HTTPTimeout, defaultHTTPTimeout)
	}
	if s.client == nil {
		t.Error("New did not install an HTTP client; the first Load would panic")
	}
}

// TestLoadConcurrentWithLookup exercises the lock. A registry load runs on a
// background goroutine while the ingest path is naming devices, which is how
// every other table in this daemon is refreshed -- without the lock that is a
// concurrent map read and write, and with luck on an unlucky run it takes the
// whole process down. Run under -race, this is the test that would catch it.
func TestLoadConcurrentWithLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fixtureOUIs))
	}))
	defer srv.Close()

	s, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	macs := []net.HardwareAddr{
		mustMAC(t, "0c:75:d2:11:22:33"),
		mustMAC(t, "d8:3a:dd:00:00:01"),
		mustMAC(t, "ff:ff:fe:00:00:01"),
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, mac := range macs {
					s.Lookup(mac)
				}
				s.Len()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := s.Load(context.Background()); err != nil {
				t.Errorf("Load: %v", err)
				return
			}
		}
	}()

	// Overlap the readers with enough reloads that the swap happens while
	// they are running.
	for i := 0; i < 50; i++ {
		if err := s.Load(context.Background()); err != nil {
			t.Fatalf("Load: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if v, ok := s.Lookup(macs[0]); !ok || v != "Hangzhou Hikvision Digital Technology Co.,Ltd." {
		t.Errorf("table lost its entries under concurrent access: (%q, %v)", v, ok)
	}
}
