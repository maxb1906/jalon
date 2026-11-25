// Package engine orchestre la cascade de sondes et publie l'avancement sur
// un bus d'événements unique, consommé indifféremment par la CLI, la TUI et
// l'UI web : le moteur ne connaît pas l'interface.
package engine

import (
	"sync"

	"github.com/maxb1906/jalon/internal/model"
)

// EventType est le type d'un événement.
type EventType string

const (
	EvRunStart    EventType = "run_start"
	EvGlobalStep  EventType = "global_step"
	EvTargetStart EventType = "target_start"
	EvStepStart   EventType = "step_start"
	EvStep        EventType = "step"
	EvTrace       EventType = "trace_update"
	EvTargetDone  EventType = "target_done"
	EvRunDone     EventType = "run_done"
)

// Event est publié sur le bus.
type Event struct {
	Type    EventType           `json:"type"`
	Target  int                 `json:"target"` // index de la cible (-1 = global)
	Raw     string              `json:"raw,omitempty"`
	StepID  string              `json:"step_id,omitempty"`
	Step    *model.Step         `json:"step,omitempty"`
	Trace   *model.TraceResult  `json:"trace,omitempty"`
	Report  *model.TargetReport `json:"report,omitempty"`
	Run     *model.Report       `json:"run,omitempty"`
	Targets []string            `json:"targets,omitempty"`
}

// Bus diffuse les événements aux abonnés, dans l'ordre, un par un.
type Bus struct {
	mu   sync.Mutex
	subs []func(Event)
}

// Subscribe ajoute un abonné. Les abonnés doivent rendre la main vite.
func (b *Bus) Subscribe(fn func(Event)) {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
}

// Emit publie un événement.
func (b *Bus) Emit(e Event) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, fn := range b.subs {
		fn(e)
	}
}
