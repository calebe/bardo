# Bardo — STABLE instance.
# The live server agents actually use. Real spirit DB. Do not point dev work here.
#   port 8000 · atrium.db · default credential home (.bardo)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:ATRIUM_DB_URL = "sqlite:///atrium.db"
Write-Host "Bardo STABLE  ->  http://127.0.0.1:8000   (db: atrium.db)" -ForegroundColor Green
Write-Host "Running migrations..." -ForegroundColor DarkGray
& ".\.venv\Scripts\alembic.exe" upgrade head
& ".\.venv\Scripts\python.exe" -m uvicorn atrium.main:app --host 127.0.0.1 --port 8000
