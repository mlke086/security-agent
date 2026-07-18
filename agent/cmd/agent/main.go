package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/security-agent/agent/internal/comm"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/enroll"
	"github.com/security-agent/agent/internal/scan"
	"github.com/security-agent/agent/internal/updater"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[agent] starting security agent v0.1.0")

	cfgPath := config.DefaultConfigPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("[agent] config not found at %s, starting enrollment flow", cfgPath)
		cfg, _ = config.Load(cfgPath)
		if cfg == nil {
			cfg = &config.Config{HeartbeatSec: 60}
		}
	}

	// P0-GO-1: honor server_public_key from config.json so first-run agents
	// with a pre-baked config also verify signed commands.
	if cfg != nil && cfg.ServerPublicKey != "" {
		if err := crypto.SetPublicKey(cfg.ServerPublicKey); err != nil {
			log.Printf("[agent] WARN: invalid server_public_key in config: %v", err)
		} else {
			log.Println("[agent] server public key configured from config.json")
		}
	}

	// If no agent_id, attempt enrollment
	if cfg.AgentID == "" && cfg.EnrollToken != "" {
		log.Println("[agent] enrolling with server...")
		resp, err := enroll.DoEnroll(cfg.ConsoleURL, cfg.EnrollToken)
		if err != nil {
			log.Fatalf("[agent] enrollment failed: %v", err)
		}
		cfg.AgentID = resp.AgentID
		cfg.AgentToken = resp.AgentToken
		cfg.HeartbeatSec = resp.HeartbeatInterval
		if err := cfg.Save(cfgPath); err != nil {
			log.Printf("[agent] failed to save config: %v", err)
		}
		log.Printf("[agent] enrolled as %s", cfg.AgentID)

		// P0-GO-1: capture the server public key from the enroll response so
		// sensitive commands can be verified. Without this every signed
		// command would fail verification.
		if resp.ServerPublicKey != "" {
			cfg.ServerPublicKey = resp.ServerPublicKey
			if err := crypto.SetPublicKey(resp.ServerPublicKey); err != nil {
				log.Printf("[agent] WARN: server public key rejected: %v", err)
			} else {
				log.Println("[agent] server public key configured from enroll response")
			}
		}
	}

	if cfg.AgentID == "" {
		log.Fatal("[agent] no agent_id configured and no enrollment token available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[agent] received shutdown signal")
		cancel()
	}()

	// Create scan engine
	engine := scan.NewScanEngine()

	// Create comm client
	client, err := comm.NewClient(cfg)
	if err != nil {
		log.Fatalf("[agent] failed to create comm client: %v", err)
	}

	// Wire scan engine callbacks to client send methods
	engine.OnStep = client.SendStep
	engine.OnResult = func(taskID, hostname string, findings []scan.Finding, batch int, isFinal bool) {
		client.SendResult(taskID, hostname, findings, batch, isFinal)
	}
	engine.OnAck = client.SendTaskAck

	// Wire client message handlers
	// Gap-1: scan_command -> scan engine
	client.OnScanCommand = func(payload json.RawMessage) {
		engine.HandleScanCommand(payload)
	}

	// Gap-3: rule_update -> updater rule hot-load
	client.OnRuleUpdate = func(payload json.RawMessage) {
		var req updater.RuleUpdateRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse rule_update: %v", err)
			client.SendUpdateAck("rule", "", false, err.Error())
			return
		}
		updater.HandleRuleUpdate(req, client.SendUpdateAck)
	}

	// agent_upgrade -> updater binary upgrade
	client.OnAgentUpgrade = func(payload json.RawMessage) {
		var req updater.UpgradeRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse agent_upgrade: %v", err)
			client.SendUpdateAck("agent", "", false, err.Error())
			return
		}
		if err := updater.HandleUpgrade(req); err != nil {
			log.Printf("[agent] upgrade failed: %v", err)
			client.SendUpdateAck("agent", req.Version, false, err.Error())
		}
		client.SendUpdateAck("agent", req.Version, true, "")
	}

	// Gap-4: config_update -> heartbeat interval + resource limit
	client.OnConfigUpdate = func(payload json.RawMessage) {
		var cfgUpdate struct {
			HeartbeatInterval int `json:"heartbeat_interval"`
			ResourceLimit     struct {
				CPUPercent int `json:"cpu_percent"`
				MemPercent int `json:"mem_percent"`
			} `json:"resource_limit"`
		}
		if err := json.Unmarshal(payload, &cfgUpdate); err != nil {
			log.Printf("[agent] failed to parse config_update: %v", err)
			client.SendUpdateAck("config", "", false, err.Error())
			return
		}
		if cfgUpdate.HeartbeatInterval > 0 {
			cfg.HeartbeatSec = cfgUpdate.HeartbeatInterval
		}
		log.Printf("[agent] config updated: heartbeat=%ds, cpu=%d%%, mem=%d%%",
			cfg.HeartbeatSec,
			cfgUpdate.ResourceLimit.CPUPercent,
			cfgUpdate.ResourceLimit.MemPercent,
		)
		client.SendUpdateAck("config", "", true, "")
	}

	log.Println("[agent] engine wired, connecting to server...")

	if err := client.Connect(ctx); err != nil {
		log.Printf("[agent] connection error: %v", err)
	}

	log.Println("[agent] shutdown complete")
}
