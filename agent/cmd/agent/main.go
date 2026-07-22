package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/security-agent/agent/internal/comm"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/enroll"
	"github.com/security-agent/agent/internal/protection"
	"github.com/security-agent/agent/internal/queue"
	"github.com/security-agent/agent/internal/scan"
	"github.com/security-agent/agent/internal/updater"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[agent] starting security agent v0.1.0")

	// Allow CONFIG_PATH override for dev / WSL testing -- in production the
	// installer writes to DefaultConfigPath() and the override is empty.
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath()
	}
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
		// F1 (2026-07-21): populate EVERY credential-bearing field from the
		// enroll response BEFORE the single cfg.Save -- otherwise the disk
		// image of config.json never carries server_public_key, and on the
		// next start the early crypto.SetPublicKey branch sees
		// cfg.ServerPublicKey=="" and silently skips. The in-memory
		// SetPublicKey still happens in this run, but the agent loses the
		// pubkey on every restart, so any signed scan_command fails
		// verify.go’s "server public key not configured" branch.
		cfg.AgentID = resp.AgentID
		cfg.AgentToken = resp.AgentToken
		cfg.HeartbeatSec = resp.HeartbeatInterval
		if resp.ServerPublicKey != "" {
			cfg.ServerPublicKey = resp.ServerPublicKey
		}
		if err := cfg.Save(cfgPath); err != nil {
			log.Printf("[agent] failed to save config: %v", err)
		}
		log.Printf("[agent] enrolled as %s", cfg.AgentID)

		// F1: load the just-saved pubkey into the verifier. Done after Save
		// so a corrupt disk write can’t leave crypto.PublicKey non-empty
		// while cfg.ServerPublicKey disagrees.
		if resp.ServerPublicKey != "" {
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
	// P1 (2026-07-18): attach a self-protection monitor. Set nil
	// to disable. When non-nil the engine bails out of a scan
	// before running matcher/nuclei and publishes the reason to the
	// console via the periodic heartbeat (StatusReason slot).
	protector := protection.NewMonitor(protection.DefaultThresholds(), runtime.NumCPU())
	engine.Protector = protector

	// P1-GO-07 (2026-07-19): open the offline queue BEFORE creating the
	// comm client so scan_result / scan_step messages dropped while the WS
	// is disconnected land in SQLite and get replayed on reconnect. Without
	// this the queue singleton inside the client stays nil and dropped
	// connections permanently lose scan results.
	offlineQ, err := queue.Open(queue.DefaultPath())
	if err != nil {
		log.Printf("[agent] WARN: failed to open offline queue: %v (continuing without persistence)", err)
		offlineQ = nil
	} else {
		defer func() {
			if cerr := offlineQ.Close(); cerr != nil {
				log.Printf("[agent] queue close error: %v", cerr)
			}
		}()
	}

	// Create comm client
	client, err := comm.NewClient(cfg)
	if err != nil {
		log.Fatalf("[agent] failed to create comm client: %v", err)
	}
	if offlineQ != nil {
		client.Queue = offlineQ
	}

	// 需求7：启动时从磁盘加载持久化的规则包，让重启后仍保留规则集（agent 二进制
	// 不内置规则，否则重启即丢、matcher 扫描产出 0 findings）。若磁盘无规则文件
	// （首次运行），ruleVersion 为空，心跳上报空串触发服务端全量下发。
	if persistedVer, perr := scan.LoadPersistedRules(); perr != nil {
		log.Printf("[agent] WARN: load persisted rules failed: %v", perr)
	} else if persistedVer != "" {
		client.SetRuleVersion(persistedVer)
		// 同步回 config.json，使下次启动直接读到最新版本（而非 enroll 时的旧值）。
		cfg.RuleVersion = persistedVer
		if serr := cfg.Save(config.DefaultConfigPath()); serr != nil {
			log.Printf("[agent] WARN: save config (rule_version) failed: %v", serr)
		}
		log.Printf("[agent] active rule version: %s", persistedVer)
	}

	// Wire scan engine callbacks to client send methods
	engine.OnStep = client.SendStep
	engine.OnResult = func(taskID, hostname string, findings []scan.Finding, batch int, isFinal bool) {
		if isFinal {
			client.SetStatusReason("")
		}
		client.SendResult(taskID, hostname, findings, batch, isFinal)
	}
	engine.OnAck = func(taskID string, accepted bool, reason string) {
		// Update the heartbeat status-reason slot so the console can
		// show why this host is paused without waiting for the next
		// scan rejection.
		client.SetStatusReason(reason)
		client.SendTaskAck(taskID, accepted, reason)
	}

	// Wire client message handlers
	// Gap-1: scan_command -> scan engine
	client.OnScanCommand = func(payload json.RawMessage) {
		engine.HandleScanCommand(payload)
	}

	// P1-GO-06 (2026-07-19): scan_cancel -> engine.CancelScan. The server
	// sends {"task_id": "..."} and we interrupt the in-flight scan so the
	// agent stops collecting / matching / running nuclei early.
	client.OnScanCancel = func(payload json.RawMessage) {
		var req struct {
			TaskID string `json:"task_id"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse scan_cancel: %v", err)
			return
		}
		engine.CancelScan(req.TaskID)
	}

	// Gap-3: rule_update -> updater rule hot-load
	client.OnRuleUpdate = func(payload json.RawMessage) {
		var req updater.RuleUpdateRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse rule_update: %v", err)
			client.SendUpdateAck("rule", "", false, err.Error())
			return
		}
		// 填充 agent 凭证用于 pack 下载鉴权（后端 /rules/pack 接受 agent_token）。
		req.AgentID = cfg.AgentID
		req.AgentToken = cfg.AgentToken
		req.CAPath = cfg.CAPath
		if err := updater.HandleRuleUpdate(req, client.SendUpdateAck); err != nil {
			log.Printf("[agent] rule_update failed: %v", err)
			return
		}
		// F-WSL (2026-07-21): record the new version on the client so the
		// next heartbeat reports it and the server stops re-pushing the
		// same pack. Without this the in-memory ruleVersion stays "" and
		// trigger_update_if_outdated keeps firing on every heartbeat.
		client.SetRuleVersion(req.RuleVersion)
		// 成功加载：更新心跳上报的 rule_version，并持久化到 config.json，
		// 使重启后心跳仍上报最新版本、服务端不再重复下发同一包。
		client.SetRuleVersion(req.RuleVersion)
		cfg.RuleVersion = req.RuleVersion
		if serr := cfg.Save(config.DefaultConfigPath()); serr != nil {
			log.Printf("[agent] WARN: save config (rule_version) after update failed: %v", serr)
		}
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
