# Start CloudSecure without overloading Docker (Windows).
# Usage (from repo root): .\scripts\start-local.ps1
# Requires Docker Desktop engine Running (green) before you run this.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Checking Docker engine..." -ForegroundColor Cyan
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker engine is not running. Open Docker Desktop, wait until it says Running, then retry."
}

Write-Host "Step 1/2: Starting database, cache, OPA (Neo4j via AuraDB in .env)..." -ForegroundColor Cyan
docker compose up -d db valkey opa
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Waiting for Postgres (up to 60s)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(60)
do {
    $h = docker compose ps db --format json 2>$null | ConvertFrom-Json
    if ($h.Health -eq "healthy") { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)

Write-Host "Step 2/2: Starting API, workers, frontend..." -ForegroundColor Cyan
docker compose up -d backend celery celery-beat frontend
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Core stack is up (deep-scan worker excluded)." -ForegroundColor Green
Write-Host "  UI:  http://localhost:3000" -ForegroundColor Green
Write-Host "  API: http://localhost:8000" -ForegroundColor Green
Write-Host ""
Write-Host "Deep scan worker (optional, heavy build):" -ForegroundColor Yellow
Write-Host "  docker compose --profile deep-scan up -d celery-deep-scan"
Write-Host ""
Write-Host "Optional local Neo4j (instead of AuraDB):" -ForegroundColor Yellow
Write-Host "  docker compose --profile local-neo4j up -d neo4j"
Write-Host "  Set NEO4J_URI=bolt://neo4j:7687 in .env"
