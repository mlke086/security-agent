#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Security Agent - Windows installer
.DESCRIPTION
  Downloads and installs the security agent as a Windows service.
.PARAMETER Token
  Enrollment token from the security console.
.PARAMETER ConsoleUrl
  URL of the security console (default: http://192.168.80.101:8000).
.EXAMPLE
  .\install.ps1 -Token "abc123"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Token,
    [string]$ConsoleUrl = "http://192.168.80.101:8000"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "[secagent] Installing security agent..." -ForegroundColor Cyan

$INSTALL_DIR = "$env:ProgramData\secagent"
$CONFIG_DIR = "$INSTALL_DIR\config"
New-Item -ItemType Directory -Force -Path $INSTALL_DIR, $CONFIG_DIR | Out-Null

# Detect arch
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "amd64" }
$OS = "windows"

# Download CA certificate
Write-Host "[secagent] Downloading CA certificate..."
try {
    Invoke-WebRequest -Uri "$ConsoleUrl/api/v1/agents/ca?token=$Token" -OutFile "$CONFIG_DIR\ca.pem" -ErrorAction SilentlyContinue
} catch {
    Write-Host "[secagent] Warning: no CA certificate" -ForegroundColor Yellow
}

# Download agent binary
Write-Host "[secagent] Downloading agent binary for $OS/$ARCH..."
Invoke-WebRequest -Uri "$ConsoleUrl/api/v1/agents/binary/$OS/$ARCH?token=$Token" -OutFile "$INSTALL_DIR\agent.exe"

# Write config
$config = @{
    console_url     = $ConsoleUrl
    ca_path         = "$CONFIG_DIR\ca.pem"
    enroll_token    = $Token
    heartbeat_sec   = 60
    resource_limit  = @{ cpu_percent = 30; mem_percent = 30 }
} | ConvertTo-Json
$config | Out-File -Encoding utf8NoBOM "$CONFIG_DIR\config.json"

# Register and start Windows service
Write-Host "[secagent] Registering Windows service..."
$service = Get-Service -Name "SecAgent" -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name "SecAgent" -Force
    sc.exe delete "SecAgent"
    Start-Sleep -Seconds 2
}
New-Service -Name "SecAgent" -BinaryPathName "$INSTALL_DIR\agent.exe" -DisplayName "Security Agent" -StartupType Automatic
Start-Service -Name "SecAgent"

Write-Host "[secagent] Installation complete. Agent is running." -ForegroundColor Green
Write-Host "[secagent] Check status: Get-Service SecAgent"
Get-Service -Name "SecAgent"
