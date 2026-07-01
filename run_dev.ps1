# Bardo — DEV instance.
# Where you build & test the platform. Throwaway DB, hot reload. Never the live spirit.
#   port 8001 · atrium-dev.db · use credential home .bardo-dev
# Point the CLI / MCP at this instance with:
#   $env:BARDO_URL = "http://127.0.0.1:8001"; $env:BARDO_HOME = ".bardo-dev"
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:ATRIUM_DB_URL = "sqlite:///atrium-dev.db"
Write-Host "Bardo DEV  ->  http://127.0.0.1:8001   (db: atrium-dev.db, hot reload)" -ForegroundColor Yellow
Write-Host "Running migrations..." -ForegroundColor DarkGray
& ".\.venv\Scripts\alembic.exe" upgrade head
& ".\.venv\Scripts\python.exe" -m uvicorn atrium.main:app --host 127.0.0.1 --port 8001 --reload
