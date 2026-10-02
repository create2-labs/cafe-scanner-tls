package scanner

import "fmt"

type deliveryDecision int

const (
	decisionStart deliveryDecision = iota
	decisionAck
	decisionBusy
)

type workState struct {
	running bool
	settled bool
}

// workGate makes a redelivery of the same scan run at most one piece of work.
// A scan that already published its terminal event is acked with no second run.
type workGate struct {
	byKey map[string]*workState
}

func newWorkGate() *workGate {
	return &workGate{byKey: map[string]*workState{}}
}

func deliveryKey(scanID string, seq uint64) string {
	if scanID != "" {
		return scanID
	}
	return fmt.Sprintf("seq:%d", seq)
}

// Begin reports whether this delivery should start work, ack a finished scan, or wait.
func (g *workGate) Begin(key string) deliveryDecision {
	st := g.byKey[key]
	if st == nil {
		st = &workState{}
		g.byKey[key] = st
	}
	if st.settled {
		return decisionAck
	}
	if st.running {
		return decisionBusy
	}
	st.running = true
	return decisionStart
}

// Finish records the end of a run. settled is true when a terminal event was published.
func (g *workGate) Finish(key string, settled bool) {
	st := g.byKey[key]
	if st == nil {
		return
	}
	st.running = false
	if settled {
		st.settled = true
	}
}
