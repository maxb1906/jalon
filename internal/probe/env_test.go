package probe

import (
	"context"
	"testing"
)

func TestEnvSmoke(t *testing.T) {
	r := Env(context.Background(), DefaultConfig())
	if r.Status == "" || r.Summary.Key == "" || r.OS == "" {
		t.Errorf("%+v", r)
	}
}
