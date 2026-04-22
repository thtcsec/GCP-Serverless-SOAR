# GCP SOAR local diagnostics for Windows / PowerShell

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PythonPath = Join-Path $ProjectRoot "..\.venv\Scripts\python.exe"
$EnvFile = Join-Path $ProjectRoot ".env"
$EnvExampleFile = Join-Path $ProjectRoot ".env.example"
$TerraformDevDir = Join-Path $ProjectRoot "terraform\environments\dev"

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message ==" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnLine {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-GcloudIdentity {
    try {
        $account = gcloud config get-value account 2>$null
        $project = gcloud config get-value project 2>$null
        if ($account -and $account -notmatch "^\(unset\)" -and $project -and $project -notmatch "^\(unset\)") {
            Write-Ok "gcloud auth OK for $account on project $project"
            return
        }
    } catch {
    }

    Write-WarnLine "gcloud auth or project config not ready. Run 'gcloud auth login' and 'gcloud config set project <id>'."
}

function Test-TerraformInitHint {
    if (!(Test-Path $TerraformDevDir)) {
        return
    }

    $lockFile = Join-Path $TerraformDevDir ".terraform.lock.hcl"
    if (Test-Path $lockFile) {
        Write-Ok "Terraform environment metadata detected in terraform\\environments\\dev"
    } else {
        Write-WarnLine "Terraform not initialized in terraform\\environments\\dev yet."
    }
}

Write-Host "GCP SOAR Doctor" -ForegroundColor Blue
Write-Host "Project: $ProjectRoot" -ForegroundColor Blue

Write-Section "Workspace"
if (Test-Path $PythonPath) {
    Write-Ok "Root virtualenv found at ..\\.venv"
    & $PythonPath --version
} else {
    Write-Fail "Missing root virtualenv Python at $PythonPath"
}

if (Test-Path $EnvFile) {
    Write-Ok ".env present"
} elseif (Test-Path $EnvExampleFile) {
    Write-WarnLine ".env missing. Copy .env.example to .env for local testing."
} else {
    Write-WarnLine "No .env or .env.example found."
}

Write-Section "Tooling"
foreach ($tool in @("gcloud", "terraform", "docker", "git")) {
    if (Test-CommandAvailable $tool) {
        Write-Ok "$tool is available"
    } else {
        Write-WarnLine "$tool is not installed or not in PATH"
    }
}

Write-Section "Cloud Access"
if (Test-CommandAvailable "gcloud") {
    Test-GcloudIdentity
}

Write-Section "Repo Hints"
Test-TerraformInitHint
if (Test-Path (Join-Path $ProjectRoot "scripts\check.ps1")) {
    Write-Ok "Local validation script available: .\\scripts\\check.ps1"
}
if (Test-Path (Join-Path $ProjectRoot "scripts\deploy.sh")) {
    Write-Ok "Deploy script available: .\\scripts\\deploy.sh dev deploy"
}

Write-Section "Next Steps"
Write-Host "1. Run .\\scripts\\check.ps1 to validate Python code before push."
Write-Host "2. Run .\\scripts\\deploy.sh dev deploy when gcloud auth and Docker are ready."
Write-Host "3. Seed a sample SCC event or Pub/Sub payload to verify workflow routing."
