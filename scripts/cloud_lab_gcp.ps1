# GCP SOAR — lab deploy / test / shutdown (PowerShell)
# Chay 1 phat:  .\scripts\cloud_lab_gcp.ps1 -Phase all -ProjectId YOUR_PROJECT_ID
# Don tien:     .\scripts\cloud_lab_gcp.ps1 -Phase shutdown -ProjectId YOUR_PROJECT_ID

param(
    [ValidateSet("preflight", "deploy", "verify", "dryrun", "benchmark", "logs", "all", "shutdown")]
    [string]$Phase = "all",
    [Parameter(Mandatory = $false)]
    [string]$ProjectId = "",
    [string]$Region = "us-central1",
    [string]$Zone = "us-central1-a",
    [int]$Runs = 5
)

# Continue: gcloud.ps1 writes success messages to stderr; Stop would abort the lab.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$TfDir = Join-Path $Root "terraform"
$Fn = "soar-incident-responder"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; throw $msg }

function Test-Preflight {
    param([string]$Proj)
    Write-Step "Preflight checks"
    if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
        Write-Fail "Thieu gcloud CLI — cai: https://cloud.google.com/sdk/docs/install"
    }
    if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) { Write-Fail "Thieu Terraform" }
    if (-not $Proj) { Write-Fail "Can -ProjectId (GCP project co billing)" }
    gcloud config set project $Proj | Out-Null
    gcloud auth application-default print-access-token 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Chua co ADC — chay: gcloud auth application-default login"
    }
    $billing = gcloud billing projects describe $Proj --format="value(billingEnabled)" 2>$null
    if ($billing -ne "True") { Write-Warn "Billing co the chua bat tren project $Proj" }
    Write-Ok "GCP project: $Proj, region: $Region"
    return @{ ProjectId = $Proj; Region = $Region; Zone = $Zone }
}

function Invoke-Deploy {
    param($Ctx)
    Write-Step "terraform init + apply"
    Push-Location $TfDir
    try {
        terraform init -input=false
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform init failed" }
        terraform apply -auto-approve -var="project_id=$($Ctx.ProjectId)"
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform apply failed" }
        Write-Ok "Apply complete"
        terraform output
    }
    finally { Pop-Location }
}

function Invoke-Verify {
    param($Ctx)
    Write-Step "Verify Cloud Function + VM"
    gcloud functions describe $Fn --region=$($Ctx.Region) --gen2 `
        --format="table(name,state,updateTime,serviceConfig.uri)"
    Push-Location $TfDir
    try {
        $vm = terraform output -raw target_vm_name
        gcloud compute instances describe $vm --zone=$($Ctx.Zone) `
            --format="table(name,status,networkInterfaces[0].accessConfigs[0].natIP)"
    }
    finally { Pop-Location }
}

function Invoke-DryRun {
    param($Ctx)
    Write-Step "Invoke dry-run qua HTTP"
    Push-Location $TfDir
    try {
        $url = terraform output -raw cloud_function_url
        $token = gcloud auth print-identity-token
        $payloadPath = Join-Path $TfDir "test-event-gcp-dryrun.json"
        if (-not (Test-Path $payloadPath)) { Write-Fail "Thieu $payloadPath" }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        curl.exe -s -X POST $url `
            -H "Authorization: Bearer $token" `
            -H "Content-Type: application/json" `
            -d "@$payloadPath" `
            -o out-gcp-dryrun.json
        $sw.Stop()
        Write-Ok "HTTP wall: $([math]::Round($sw.Elapsed.TotalMilliseconds, 2)) ms"
        Get-Content out-gcp-dryrun.json
    }
    finally { Pop-Location }
}

function Invoke-Benchmark {
    param($Ctx, [int]$N)
    Write-Step "Benchmark x$N"
    Push-Location $TfDir
    try {
        $url = terraform output -raw cloud_function_url
        $token = gcloud auth print-identity-token
        $payloadPath = Join-Path $TfDir "test-event-gcp-dryrun.json"
        for ($i = 1; $i -le $N; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            curl.exe -s -X POST $url -H "Authorization: Bearer $token" `
                -H "Content-Type: application/json" -d "@$payloadPath" -o "out-gcp-bench-$i.json" | Out-Null
            $sw.Stop()
            Write-Host "  Run $i : $([math]::Round($sw.Elapsed.TotalMilliseconds, 2)) ms"
        }
    }
    finally { Pop-Location }
}

function Show-Logs {
    param($Ctx)
    Write-Step "Cloud Logging"
    gcloud functions logs read $Fn --region=$($Ctx.Region) --gen2 --limit=25
}

function Invoke-Shutdown {
    param($Ctx)
    Write-Step "terraform destroy"
    Push-Location $TfDir
    try {
        terraform destroy -auto-approve -var="project_id=$($Ctx.ProjectId)"
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform destroy failed" }
        Write-Ok "Destroy complete"
    }
    finally { Pop-Location }
}

switch ($Phase) {
    "preflight" { $null = Test-Preflight -Proj $ProjectId }
    "deploy" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-Deploy $ctx
    }
    "verify" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-Verify $ctx
    }
    "dryrun" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-DryRun $ctx
    }
    "benchmark" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-Benchmark $ctx $Runs
    }
    "logs" {
        $ctx = Test-Preflight -Proj $ProjectId
        Show-Logs $ctx
    }
    "shutdown" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-Shutdown $ctx
    }
    "all" {
        $ctx = Test-Preflight -Proj $ProjectId
        Invoke-Deploy $ctx
        Invoke-Verify $ctx
        Invoke-DryRun $ctx
        Invoke-Benchmark $ctx $Runs
        Show-Logs $ctx
        Write-Step "XONG — len GCP Console chup anh"
        Write-Host @"

Console:
  1. Cloud Run functions > soar-incident-responder
  2. Logs tab
  3. Compute Engine > VM lab

Shutdown:
  .\scripts\cloud_lab_gcp.ps1 -Phase shutdown -ProjectId "$ProjectId"
"@ -ForegroundColor Yellow
    }
}
