# Go Agent cross-platform build for Windows PowerShell.
#
# Equivalent to `make build-all` on Unix. Run from the agent/ directory:
#
#     .\build.ps1                # build for linux/amd64 + linux/arm64 + windows/amd64
#     .\build.ps1 -Target amd64  # build only for amd64 (all OSes)
#     .\build.ps1 -Target linux  # build only linux variants
#     .\build.ps1 -Clean        # remove the dist/ directory
#
# Output: ..\deployments\agent\dist\<os>\<arch>\agent[.exe]
# Same paths the FastAPI /api/v1/agents/binary/<os>/<arch> endpoint reads.

[CmdletBinding()]
param(
    [ValidateSet("all", "amd64", "arm64", "linux", "windows")]
    [string]$Target = "all",
    [switch]$Clean
)

# Move $GOPATH aside for the duration of this script so Go does not emit
# "ignoring go.mod in $GOPATH" warnings (the agent/ module lives outside $GOPATH).
if ($env:GOPATH) {
    $script:OriginalGOPATH = $env:GOPATH
    Remove-Item Env:\GOPATH -ErrorAction SilentlyContinue
}
$env:GO111MODULE = "on"

$script:DIST = Join-Path $PSScriptRoot "..\deployments\agent\dist"
$script:LDFLAGS = "-s -w"

function Build-One {
    param([string]$GOOS, [string]$GOARCH, [string]$Output)
    $dir = Split-Path $Output -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Write-Host "Building $GOOS/$GOARCH -> $Output" -ForegroundColor Cyan
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH

    # Capture go's stderr to a temp file so we can surface errors without
    # PowerShell's strict mode treating warnings as terminating errors.
    $stderr_file = [System.IO.Path]::GetTempFileName()
    $stderr_text = ""
    try {
        go build -ldflags $script:LDFLAGS -o $Output ./cmd/agent 2> $stderr_file
        $rc = $LASTEXITCODE
        if (Test-Path $stderr_file) {
            $stderr_text = Get-Content $stderr_file -Raw -ErrorAction SilentlyContinue
        }
    } finally {
        if (Test-Path $stderr_file) {
            Remove-Item $stderr_file -Force -ErrorAction SilentlyContinue
        }
    }

    if ($rc -ne 0) {
        if ($stderr_text) { Write-Host $stderr_text -ForegroundColor Red }
        throw "go build failed for $GOOS/$GOARCH (exit $rc)"
    }
    if ($stderr_text -and $stderr_text.Trim()) {
        Write-Host "  (warning) $($stderr_text.Trim())" -ForegroundColor DarkYellow
    }
    $size = (Get-Item $Output).Length
    Write-Host "  OK  $([math]::Round($size / 1MB, 2)) MB" -ForegroundColor Green
}

try {
    if ($Clean) {
        if (Test-Path $script:DIST) {
            Remove-Item -Recurse -Force $script:DIST
            Write-Host "Removed $script:DIST" -ForegroundColor Yellow
        }
        return
    }

    $jobs = @()
    switch ($Target) {
        "amd64" {
            $jobs += @{ GOOS = "linux";   GOARCH = "amd64"; Output = "$script:DIST\linux\amd64\agent" }
            $jobs += @{ GOOS = "windows"; GOARCH = "amd64"; Output = "$script:DIST\windows\amd64\agent.exe" }
        }
        "arm64" {
            $jobs += @{ GOOS = "linux";   GOARCH = "arm64"; Output = "$script:DIST\linux\arm64\agent" }
        }
        "linux" {
            $jobs += @{ GOOS = "linux";   GOARCH = "amd64"; Output = "$script:DIST\linux\amd64\agent" }
            $jobs += @{ GOOS = "linux";   GOARCH = "arm64"; Output = "$script:DIST\linux\arm64\agent" }
        }
        "windows" {
            $jobs += @{ GOOS = "windows"; GOARCH = "amd64"; Output = "$script:DIST\windows\amd64\agent.exe" }
        }
        default {
            $jobs += @{ GOOS = "linux";   GOARCH = "amd64"; Output = "$script:DIST\linux\amd64\agent" }
            $jobs += @{ GOOS = "linux";   GOARCH = "arm64"; Output = "$script:DIST\linux\arm64\agent" }
            $jobs += @{ GOOS = "windows"; GOARCH = "amd64"; Output = "$script:DIST\windows\amd64\agent.exe" }
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($j in $jobs) {
        Build-One -GOOS $j.GOOS -GOARCH $j.GOARCH -Output $j.Output
    }
    $sw.Stop()
    Write-Host ""
    Write-Host "Done in $($sw.Elapsed.TotalSeconds.ToString('0.1'))s. Output: $script:DIST" -ForegroundColor Green
} finally {
    if ($script:OriginalGOPATH) {
        $env:GOPATH = $script:OriginalGOPATH
    }
}
