// Package response implements server-driven response actions on the Agent.
//
// Phase 4 of docs/Agent监控告警改造方案.md. Operators dispatch a small set of
// defensive actions (kill_process, quarantine_file) from the console to a
// specific Agent. The Agent verifies the Ed25519 signature on the WS
// message (same path as scan_command / rule_update), looks up the action
// in this dispatcher, executes it, and ships back a response_ack with
// the outcome.
//
// Threat model:
//   - Server signature is the only authorization. The Agent rejects any
//     response_action whose Ed25519 signature does not verify against the
//     pubkey pinned at enrollment.
//   - The action catalogue is a whitelist (SupportedActions below). The
//     server cannot ask the Agent to run an unknown op_type even if it
//     forges a signed payload -- the lookup table simply has no entry.
//   - KillProcess refuses to target the Agent's own PID.
package response

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// SupportedActions is the canonical list of action names this dispatcher
// knows how to run. Keep in sync with src/agents/response_actions.py
// (server side). The Agent refuses anything outside this set.
var SupportedActions = map[string]ActionHandler{
	"kill_process":    KillProcess,
	"quarantine_file": QuarantineFile,
}

// ActionHandler runs one action and returns a Result describing what
// happened. Implementations MUST NOT panic on bad input -- the dispatcher
// catches errors, but a panic inside the goroutine that called Handle()
// would still tear down the connection.
type ActionHandler func(params json.RawMessage) Result

// Result is the payload sent back to the server as ``response_ack``.
//
// ``Ok`` distinguishes "ran successfully" from "ran but failed" (e.g.
// tried to kill a PID that does not exist). Either way the action is
// considered ``executed``; the operator polls /actions/{id} for the
// terminal state.
type Result struct {
	Ok     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Envelope is the inner payload of a ``response_action`` WS message.
//
// The server fills this in src/agents/response_actions.py; keep the JSON
// tags identical.
type Envelope struct {
	ActionID string          `json:"action_id"`
	Action   string          `json:"action"`
	Params   json.RawMessage `json:"params"`
	Actor    string          `json:"actor"`
	IssuedAt string          `json:"issued_at"`
}

// Dispatcher routes incoming Envelopes to the registered ActionHandler.
// One dispatcher per Agent process is plenty; the methods are safe for
// concurrent calls because SupportedActions is immutable after package
// init.
type Dispatcher struct {
	mu sync.Mutex
	// ack is supplied by main.go so the dispatcher does not need to
	// know about the comm package directly. Filled in via New().
	ack func(actionID string, ok bool, detail string)
}

// New returns a Dispatcher that sends acks through ``ackFn``.
//
// ``ackFn`` is normally ``client.SendResponseAck`` wired up in main.go.
func New(ackFn func(actionID string, ok bool, detail string)) *Dispatcher {
	return &Dispatcher{ack: ackFn}
}

// Handle runs the action described by ``raw`` and emits a response_ack.
//
// Runs synchronously -- the server sees ``response_ack`` only after the
// action returns. For kill/quarantine this is fine (sub-millisecond on a
// healthy host; we still surface errors via the ack).
func (d *Dispatcher) Handle(raw json.RawMessage) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		log.Printf("[response] malformed envelope: %v", err)
		return
	}
	handler, ok := SupportedActions[env.Action]
	if !ok {
		d.send(env.ActionID, false, fmt.Sprintf("unsupported action: %s", env.Action))
		return
	}
	result := handler(env.Params)
	d.send(env.ActionID, result.Ok, result.Detail)
}

func (d *Dispatcher) send(actionID string, ok bool, detail string) {
	if d.ack == nil {
		log.Printf("[response] ack sink missing; action_id=%s ok=%v detail=%s", actionID, ok, detail)
		return
	}
	d.ack(actionID, ok, detail)
}
