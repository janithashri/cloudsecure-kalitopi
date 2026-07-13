# Run from repo root before first public push.
# Verifies .env is ignored and scans tracked files for common secret patterns.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Checking .gitignore for .env..." -ForegroundColor Cyan
if (-not (Test-Path .gitignore)) { throw ".gitignore missing" }
$ignore = Get-Content .gitignore -Raw
if ($ignore -notmatch '(?m)^\.env\s*$') { throw ".env must be listed in .gitignore" }
Write-Host "  OK" -ForegroundColor Green

$patterns = @(
    '115503922806',
    '416911025124',
    'AKIA[0-9A-Z]{16}',
    'neo4j\+s://[a-f0-9-]+\.databases\.neo4j\.io'
)

$files = Get-ChildItem -Recurse -File |
    Where-Object {
        $_.FullName -notmatch '\\(\.git|node_modules|venv|\.venv|__pycache__|output|dist)(\\|$)' -and
        $_.Name -ne '.env' -and
        $_.Name -notmatch '^\.env\.' -and
        $_.Name -ne 'frontend\.env'
    }

$hits = @()
foreach ($file in $files) {
    if ($file.Name -eq 'prepare-public-push.ps1') { continue }
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) {
            $hits += [pscustomobject]@{ File = $file.FullName; Pattern = $pattern }
        }
    }
}

if ($hits.Count -gt 0) {
    Write-Host "POSSIBLE SECRETS FOUND - fix before pushing:" -ForegroundColor Red
    $hits | Format-Table -AutoSize
    exit 1
}

Write-Host "No common secret patterns found in project files." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  git init"
Write-Host "  git add ."
Write-Host "  git status   # confirm .env is NOT listed"
Write-Host "  git commit -m ""Initial public release: FastAPI backend, AuraDB graph"""
Write-Host "  gh repo create cloudsecure --public --source=. --push"
Write-Host "  # or: git remote add origin https://github.com/YOUR_USER/cloudsecure.git && git push -u origin main"
