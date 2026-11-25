//go:build !windows

package probe

import "testing"

func TestParseResolvConf(t *testing.T) {
	got := parseResolvConf("# commentaire\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nsearch lan\nnameserver bad\n")
	if len(got) != 2 || got[0] != "127.0.0.53" || got[1] != "fe80::1" {
		t.Errorf("%v", got)
	}
}
