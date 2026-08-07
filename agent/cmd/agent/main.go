package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/security-agent/agent/internal/comm"
	"github.com/security-agent/agent/internal/config"
	"github.com/security-agent/agent/internal/crypto"
	"github.com/security-agent/agent/internal/enroll"
	"github.com/security-agent/agent/internal/metrics"
	"github.com/security-agent/agent/internal/monitor"
	"github.com/security-agent/agent/internal/protection"
	"github.com/security-agent/agent/internal/queue"
	"github.com/security-agent/agent/internal/response"
	"github.com/security-agent/agent/internal/resource"
	"github.com/security-agent/agent/internal/scan"
	"github.com/security-agent/agent/internal/scan/nuclei"
	"github.com/security-agent/agent/internal/updater"
	"github.com/security-agent/agent/internal/version"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[agent] starting security agent v%s", version.Version)

	// Allow CONFIG_PATH override for dev / WSL testing -- in production the
	// installer writes to DefaultConfigPath() and the override is empty.
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// V13 P2-19: the second Load call's result was discarded -- load
		// once, and fall back to defaults when the file is missing/corrupt.
		log.Printf("[agent] config load failed at %s (%v), using defaults", cfgPath, err)
		cfg = &config.Config{HeartbeatSec: 60}
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

	// Stamp the compiled-in version so heartbeat can report it.
	cfg.AgentVersion = version.Version

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

	// Create scan engine. V13 P2-17: pass the root context so agent_shutdown
	// cancels in-flight scans too (not just the WS connection).
	engine := scan.NewScanEngine(ctx)
	// P1 (2026-07-18): attach a self-protection monitor. Set nil
	// to disable. When non-nil the engine bails out of a scan
	// before running matcher/nuclei and publishes the reason to the
	// console via the periodic heartbeat (StatusReason slot).
	protector := protection.NewMonitor(protection.DefaultThresholds(), runtime.NumCPU())
	engine.Protector = protector

	// V13 P1-13: wire the resource-limit monitor into the scan engine so
	// server-pushed resource_limit (config_update) actually throttles scans.
	// Previously engine.Monitor stayed nil and IsThrottling never fired;
	// the 10s sampling window matches the 5s throttle pause in the engine.
	resMonitor := resource.NewMonitor(resource.Limit{})
	resMonitor.Start(10 * time.Second)
	defer resMonitor.Stop()
	engine.Monitor = resMonitor

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
		// G-P1-3 (V12): save to cfgPath (the CONFIG_PATH override) instead of
		// DefaultConfigPath -- a dev/test override was being written to the
		// default path, so a restart without CONFIG_PATH re-pushed the pack.
		cfg.RuleVersion = persistedVer
		if serr := cfg.Save(cfgPath); serr != nil {
			log.Printf("[agent] WARN: save config (rule_version) failed: %v", serr)
		}
		log.Printf("[agent] active rule version: %s", persistedVer)
	}

	// Detect the installed nuclei CLI version once at startup so the first
	// heartbeat reports it. The server compares this against the
	// Nacos-configured NUCLEI_VERSION and pushes a nuclei_upgrade when they
	// diverge. Empty string (nuclei absent) is reported as-is -- the server
	// treats that as "needs install" and pushes the upgrade.
	if nv := nuclei.DetectDefaultVersion(); nv != "" {
		client.SetNucleiVersion(nv)
		log.Printf("[agent] active nuclei version: %s", nv)
	} else {
		log.Printf("[agent] nuclei not installed; server may push a nuclei_upgrade")
	}

	// Wire scan engine callbacks to client send methods
	engine.OnStep = client.SendStep
	engine.OnResult = func(taskID, hostname string, findings []scan.Finding, batch int, isFinal bool, scannedCategories []string) {
		if isFinal {
			client.SetStatusReason("")
		}
		client.SendResult(taskID, hostname, findings, batch, isFinal, scannedCategories)
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
		// V10 P2 (V12): SetRuleVersion was called twice (merge residue).
		client.SetRuleVersion(req.RuleVersion)
		// 成功加载：更新心跳上报的 rule_version，并持久化到 config.json，
		// 使重启后心跳仍上报最新版本、服务端不再重复下发同一包。
		cfg.RuleVersion = req.RuleVersion
		// G-P1-3 (V12): save to cfgPath, not DefaultConfigPath.
		if serr := cfg.Save(cfgPath); serr != nil {
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
		req.AgentID = cfg.AgentID
		req.AgentToken = cfg.AgentToken
		req.CAPath = cfg.CAPath
		// P2-UPGRADE-02 (2026-07-22): the previous version called os.Exit
		// on success so the server never saw a confirmed ack. We now
		// validate + swap the binary on disk, ack the server immediately,
		// then ask the runtime to restart in the background.
		if err := updater.HandleUpgrade(req); err != nil {
			log.Printf("[agent] upgrade failed: %v", err)
			client.SendUpdateAck("agent", req.Version, false, err.Error())
			return
		}
		client.SendUpdateAck("agent", req.Version, true, "")
		go func(req updater.UpgradeRequest) {
			if err := updater.ApplyStagedAndRestart(req, cfg); err != nil {
				// G-P1-2 (V12): do NOT send a second (failure) ack after the
				// success ack above -- the server would overwrite the
				// "restarting" state with "failed" and never self-heal.
				// V13 P1-10: HandleUpgrade had already swapped the NEW binary
				// onto disk (old one at execPath+".old"); ApplyStagedAndRestart
				// restores the old binary when the restart cannot be started.
				// The next heartbeat still reports the old version and the
				// server's version-mismatch logic re-pushes the upgrade.
				log.Printf("[agent] restart failed: %v (old binary restored; no second ack; heartbeat mismatch will re-push)", err)
			}
		}(req)
	}

	// nuclei_upgrade -> swap the nuclei CLI binary in place. Unlike
	// agent_upgrade this needs no restart: nuclei is spawned as a fresh
	// subprocess per scan, so the next scan picks up the new binary. After a
	// successful swap we re-detect the version and stamp it onto the
	// heartbeat slot so the server sees the new version and stops re-pushing.
	client.OnNucleiUpgrade = func(payload json.RawMessage) {
		var req updater.NucleiUpgradeRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse nuclei_upgrade: %v", err)
			client.SendUpdateAck("nuclei", "", false, err.Error())
			return
		}
		req.CAPath = cfg.CAPath
		if err := updater.HandleNucleiUpgrade(req, client.SendUpdateAck); err != nil {
			log.Printf("[agent] nuclei upgrade failed: %v", err)
			return
		}
		// Re-detect and report so the server's next version compare matches.
		newVer := nuclei.DetectDefaultVersion()
		client.SetNucleiVersion(newVer)
		log.Printf("[agent] nuclei upgrade complete, reported version: %q", newVer)
	}

	// nuclei_templates_update -> swap the nuclei-templates bundle in
	// /opt/secagent/templates. Triggered manually from the rules page「同步
	// Nuclei 模板」button. No restart: the next nuclei scan reads -t <dir>
	// fresh, so it picks up the new templates immediately.
	client.OnNucleiTemplatesUpdate = func(payload json.RawMessage) {
		var req updater.NucleiTemplatesUpdateRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			log.Printf("[agent] failed to parse nuclei_templates_update: %v", err)
			client.SendUpdateAck("nuclei_templates", "", false, err.Error())
			return
		}
		req.CAPath = cfg.CAPath
		if err := updater.HandleNucleiTemplatesUpdate(req, client.SendUpdateAck); err != nil {
			log.Printf("[agent] nuclei templates update failed: %v", err)
			return
		}
		log.Printf("[agent] nuclei templates v%s installed", req.Version)
	}

	// Gap-4: config_update -> heartbeat interval + resource limit + metrics 配置
	// 需求①: metricsReporter 在下方 hostMonitor 之后创建并 Run；这里先声明
	// 供闭包引用（执行时非 nil 才应用），避免在闭包定义处强依赖初始化顺序。
	var metricsReporter *metrics.Reporter
	client.OnConfigUpdate = func(payload json.RawMessage) {
		var cfgUpdate struct {
			HeartbeatInterval int `json:"heartbeat_interval"`
			// 需求①: host_metrics 上报间隔（秒）与磁盘采样挂载点。
			MetricsIntervalSec int      `json:"metrics_interval_sec"`
			MetricsMounts      []string `json:"metrics_mounts"`
			ResourceLimit      struct {
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
			// V9 5.1: actually apply the new interval to the running
			// heartbeat ticker (was a no-op -- ticker was created once
			// at connect time with the old interval).
			client.ApplyHeartbeatInterval(cfgUpdate.HeartbeatInterval)
		}
		// V13 P1-13: apply the resource limit to the live monitor so the
		// engine's IsThrottling check (between scan modules) starts
		// respecting the operator's limits immediately.
		resMonitor.UpdateLimit(resource.Limit{
			CPUPercent: cfgUpdate.ResourceLimit.CPUPercent,
			MemPercent: cfgUpdate.ResourceLimit.MemPercent,
		})
		// 需求①: hot-apply metrics interval / disk mount without restarting
		// the reporter loop.
		if cfgUpdate.MetricsIntervalSec > 0 {
			cfg.MetricsIntervalSec = cfgUpdate.MetricsIntervalSec
			if metricsReporter != nil {
				metricsReporter.UpdateInterval(cfgUpdate.MetricsIntervalSec)
			}
		}
		if len(cfgUpdate.MetricsMounts) > 0 {
			cfg.MetricsMounts = cfgUpdate.MetricsMounts
			resMonitor.UpdateMount(cfgUpdate.MetricsMounts[0])
		}
		log.Printf("[agent] config updated: heartbeat=%ds, cpu=%d%%, mem=%d%%, metrics_interval=%ds",
			cfg.HeartbeatSec,
			cfgUpdate.ResourceLimit.CPUPercent,
			cfgUpdate.ResourceLimit.MemPercent,
			cfg.MetricsIntervalSec,
		)
		client.SendUpdateAck("config", "", true, "")
	}

	// Phase 4: response_action dispatcher. Holds the catalogue of allowed
	// server-dispatched actions (kill_process / quarantine_file) and runs
	// them on this host. Acks are sent back through the same WS connection
	// using SendResponseAck, which the server's AgentGateway._record_response_ack
	// mirrors into a per-action Redis status key.
	respDispatcher := response.New(client.SendResponseAck)
	client.OnResponseAction = func(payload json.RawMessage) {
		respDispatcher.Handle(payload)
	}

	// agent_shutdown: server sends this when the operator decommissions
	// the host. Cancel the root context so Connect() returns, all defers
	// run (monitor.Stop, queue.Close, engine cleanup), and the process
	// exits cleanly. The systemd unit Restart=no ensures it stays down.
	client.OnShutdown = func() {
		log.Println("[agent] server requested shutdown, cancelling root context")
		cancel()
	}

	// Phase 5: lightweight host monitor. Polls the process table every
	// MonitorIntervalSec and ships a snapshot up the WS as ``monitor_event``.
	// The default is 30s (rather than 3-5s) because the snapshot payload
	// is ~ a few hundred process rows; 30s is a sweet spot for
	// "near-real-time view of what is running" without flooding the WS
	// for hosts with thousands of processes. Operators can override via
	// env if they have a fleet small enough for tighter polling.
	monitorInterval := time.Duration(getMonitorIntervalSec()) * time.Second
	hostMonitor := monitor.New(monitor.RealLister{}, clientMonitorSink(client), monitorInterval, 0)
	hostMonitor.Start(ctx)
	defer hostMonitor.Stop()

	// 需求①: 主机性能指标上报。独立于心跳与进程监控：每
	// cfg.MetricsIntervalSec（默认 15s）经 resource.Monitor.Sample() 采集
	// cpu/mem/disk/net/load，走 host_metrics 非排队通道（断线即丢，
	// 不入离线队列）。生命周期随 rootCtx —— 取消即停。
	metricsReporter = metrics.NewReporter(resMonitor, client, cfg.MetricsIntervalSec)
	metricsReporter.Run(ctx)
	defer metricsReporter.Stop()

	log.Println("[agent] engine wired, connecting to server...")

	if err := client.Connect(ctx); err != nil {
		log.Printf("[agent] connection error: %v", err)
	}

	log.Println("[agent] shutdown complete")
}

// clientMonitorSink adapts comm.Client.SendMonitorEvent (which takes
// an opaque ``interface{}`` payload) to monitor.Sink (which expects a
// concrete monitor.Snapshot). Kept as a free function so it does not
// pull a circular import into agent/internal/monitor.
func clientMonitorSink(c *comm.Client) monitor.Sink {
	return monitor.SinkFunc(func(s monitor.Snapshot) {
		c.SendMonitorEvent(s)
	})
}

// getMonitorIntervalSec reads MONITOR_INTERVAL_SEC from env (default 30s).
// Split out of main() so tests can call it without standing up the full
// Agent; range-clamped so a typo in production cannot stall the monitor
// at e.g. 0s (per-second polling would saturate the WS).
func getMonitorIntervalSec() int {
	raw := os.Getenv("MONITOR_INTERVAL_SEC")
	if raw == "" {
		return 30
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 5 {
		return 30
	}
	return n
}
