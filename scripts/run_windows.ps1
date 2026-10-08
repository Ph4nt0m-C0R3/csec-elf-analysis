$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$venvRoot = Join-Path $projectRoot ".venvs"
$machineName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "windows" }
$venvPath = Join-Path $venvRoot ("windows-" + $machineName)
$stampFile = Join-Path $venvPath ".requirements.sha256"

function Get-VenvPython {
    $candidates = @(
        (Join-Path $venvPath "Scripts\python.exe"),
        (Join-Path $venvPath "bin\python.exe"),
        (Join-Path $venvPath "bin\python")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function New-Venv {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & py -3 -m venv $venvPath
        return
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        & python -m venv $venvPath
        return
    }

    throw "Python 3.11 or newer was not found. Install Python, then reopen PowerShell."
}

$pythonExe = Get-VenvPython

if (-not $pythonExe) {
    New-Item -ItemType Directory -Force -Path $venvRoot | Out-Null
    New-Venv
    $pythonExe = Get-VenvPython
}

if (-not $pythonExe) {
    throw "The virtual environment was created, but its Python executable could not be found."
}

& $pythonExe -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    $pythonVersion = (& $pythonExe --version)
    throw "Python 3.11 or newer is required. This environment uses $pythonVersion at $pythonExe."
}

$requirementsHash = (Get-FileHash -Algorithm SHA256 -Path "requirements.txt").Hash
$installedHash = if (Test-Path $stampFile) {
    (Get-Content -Raw -LiteralPath $stampFile).Trim()
} else {
    ""
}

if ($installedHash -ne $requirementsHash) {
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install -r requirements.txt
    Set-Content -LiteralPath $stampFile -Value $requirementsHash
}

& $pythonExe scripts\init_db.py

if (-not $env:REVLEARN_SECRET_KEY) {
    $env:REVLEARN_SECRET_KEY = (& $pythonExe -c "import secrets; print(secrets.token_hex(32))")
}

if (-not $env:REVLEARN_HOST) {
    $env:REVLEARN_HOST = "127.0.0.1"
}

if (-not $env:REVLEARN_PORT) {
    $env:REVLEARN_PORT = "5000"
}

Write-Host ""
Write-Host "Reverse Engineering Learning System"
Write-Host "Project: $projectRoot"
Write-Host "Python:  $pythonExe"
Write-Host "Open:    http://$env:REVLEARN_HOST`:$env:REVLEARN_PORT"
Write-Host "Stop:    Ctrl+C"
Write-Host ""

& $pythonExe app.py
