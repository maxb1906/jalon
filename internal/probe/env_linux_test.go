//go:build linux

package probe

import "testing"

func TestParseProcRoute(t *testing.T) {
	data := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	got := parseProcRoute(data)
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Errorf("%v", got)
	}
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
	if g := parseProcIPv6Route(v6); len(g) != 1 || g[0] != "fe80::1%eth0" {
		t.Errorf("v6 %v", g)
	}
}

func TestCapAndPing(t *testing.T) {
	if !capNetRaw("Name:\tx\nCapEff:\t0000000000002000\n") || capNetRaw("CapEff:\t0000000000000000\n") {
		t.Error("capNetRaw")
	}
	if !pingAllowed("0\t2147483647", []int{1000}) || pingAllowed("1\t0", []int{1000}) {
		t.Error("pingAllowed")
	}
}
