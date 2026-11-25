//go:build !linux && !darwin && !windows

package probe

import (
	"os"

	"github.com/maxb1906/jalon/internal/model"
)

func osGateways() []string { return nil }

func osProxies(r *model.EnvResult) {}

func osPrivileges(p *model.Privileges) {
	p.Admin = os.Geteuid() == 0
	if p.Admin {
		p.ICMPTrace, p.ICMPMethod = true, "raw"
		p.TCPTrace, p.TCPMethod = true, "connect+raw-icmp"
	}
}
