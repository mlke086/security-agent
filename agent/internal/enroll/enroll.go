package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"os/exec"
	"strings"
)

// EnrollResponse is returned by the server after successful enrollment.
type EnrollResponse struct {
	AgentID           string `json:"agent_id"`
	AgentToken        string `json:"agent_token"`
	WSURL             string `json:"ws_url"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	// ServerPublicKey is the hex-encoded Ed25519 public key used to verify
	// signed sensitive commands (scan_command / rule_update / ...). P0-GO-1.
	ServerPublicKey   string `json:"server_public_key"`
}

// EnrollRequest is sent to the server for enrollment.
type EnrollRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	IP       string `json:"ip"`
	Kernel   string `json:"kernel"`
}

// DoEnroll sends an enrollment request to the server.
func DoEnroll(consoleURL, enrollToken string) (*EnrollResponse, error) {
	hostname, _ := os.Hostname()

	req := EnrollRequest{
		Token:    enrollToken,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		IP:       getLocalIP(),
		Kernel:   getKernelVersion(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal enroll request: %w", err)
	}

	resp, err := http.Post(
		consoleURL+"/api/v1/agents/enroll",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enroll failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}

	if enrollResp.HeartbeatInterval <= 0 {
		enrollResp.HeartbeatInterval = 60
	}

	return &enrollResp, nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
	}
	h, _ := os.Hostname()
	return h
}

func getKernelVersion() string {
	if runtime.GOOS == "windows" {
		return "Windows"
	}
	out, err := exec.Command("uname", "-r").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "Linux"
}
