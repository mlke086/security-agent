package enroll

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoEnrollSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/enroll" {
			t.Errorf("path = %s, want /api/v1/agents/enroll", r.URL.Path)
		}
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: "a1", AgentToken: "tok", WSURL: "wss://x", HeartbeatInterval: 30})
	}))
	defer srv.Close()

	resp, err := DoEnroll(srv.URL, "enroll-token")
	if err != nil {
		t.Fatalf("DoEnroll: %v", err)
	}
	if resp.AgentID != "a1" || resp.AgentToken != "tok" || resp.WSURL != "wss://x" || resp.HeartbeatInterval != 30 {
		t.Errorf("resp mismatch: %+v", resp)
	}
}

func TestDoEnrollFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := DoEnroll(srv.URL, "bad"); err == nil {
		t.Error("expected error on 401")
	}
}

func TestDoEnrollDefaultHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: "a", AgentToken: "t", WSURL: "wss://x"})
	}))
	defer srv.Close()

	resp, err := DoEnroll(srv.URL, "tok")
	if err != nil {
		t.Fatalf("DoEnroll: %v", err)
	}
	if resp.HeartbeatInterval != 60 {
		t.Errorf("default HeartbeatInterval = %d, want 60", resp.HeartbeatInterval)
	}
}
