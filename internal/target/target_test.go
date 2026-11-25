package target

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in, proto   string
		host        string
		port        int
		wantProto   string
		implicitTLS bool
		isIP        bool
		path        string
	}{
		{"https://exemple.be", "", "exemple.be", 443, "https", true, false, "/"},
		{"http://exemple.be:8080/a?b=1", "", "exemple.be", 8080, "http", false, false, "/a?b=1"},
		{"exemple.be", "", "exemple.be", 443, "https", true, false, "/"},
		{"Exemple.BE.", "", "exemple.be", 443, "https", true, false, "/"},
		{"smtp://mail.exemple.be", "", "mail.exemple.be", 25, "smtp", false, false, ""},
		{"smtps://mail.exemple.be", "", "mail.exemple.be", 465, "smtp", true, false, ""},
		{"submission://mail.exemple.be", "", "mail.exemple.be", 587, "smtp", false, false, ""},
		{"imaps://mail.exemple.be", "", "mail.exemple.be", 993, "imap", true, false, ""},
		{"10.0.0.5:3389", "", "10.0.0.5", 3389, "rdp", false, true, ""},
		{"10.0.0.5", "", "10.0.0.5", 443, "https", true, true, "/"},
		{"[2001:db8::1]:22", "", "2001:db8::1", 22, "ssh", false, true, ""},
		{"2001:db8::1", "", "2001:db8::1", 443, "https", true, true, "/"},
		{"host:5432", "", "host", 5432, "banner", false, false, ""},
		{"host:993", "", "host", 993, "imap", true, false, ""},
		{"host:2525", "smtp", "host", 2525, "smtp", false, false, ""},
		{"host:636", "ldap", "host", 636, "ldap", true, false, ""},
		{"ldap://dc.corp.local", "", "dc.corp.local", 389, "ldap", false, false, ""},
		{"tls://host:8883", "", "host", 8883, "banner", true, false, ""},
		{"exemple.be/chemin", "", "exemple.be", 443, "https", true, false, "/chemin"},
	}
	for _, c := range cases {
		got, err := Parse(c.in, c.proto)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got.Host != c.host || got.Port != c.port || got.Proto != c.wantProto ||
			got.ImplicitTLS != c.implicitTLS || got.IsIP != c.isIP || got.Path != c.path {
			t.Errorf("Parse(%q) = %+v", c.in, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "foo://x", "tcp://host", "host:0", "host:99999", "bad host", "x:22/"} {
		if _, err := Parse(in, ""); err == nil {
			t.Errorf("Parse(%q) aurait dû échouer", in)
		}
	}
	if _, err := Parse("host", "gopher"); err == nil {
		t.Error("proto inconnu accepté")
	}
}

func TestURL(t *testing.T) {
	tg, _ := Parse("http://[2001:db8::1]:8080/x", "")
	if u := URL(tg); u != "http://[2001:db8::1]:8080/x" {
		t.Errorf("URL = %s", u)
	}
	tg, _ = Parse("exemple.be", "")
	if u := URL(tg); u != "https://exemple.be/" {
		t.Errorf("URL = %s", u)
	}
}

func TestReadList(t *testing.T) {
	l, err := ReadList(strings.NewReader("# liste\nexemple.be\n\n  smtp://mail.x # mail\n#fin\n"))
	if err != nil || len(l) != 2 || l[0] != "exemple.be" || l[1] != "smtp://mail.x" {
		t.Errorf("ReadList = %v, %v", l, err)
	}
}
