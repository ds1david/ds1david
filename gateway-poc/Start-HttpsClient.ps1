[CmdletBinding()]
param(
    [ValidateSet('Check','Query','Forward')][string]$Mode = 'Query',
    [ValidateSet('lab-status','lab-catalog','lab-echo','gitlab','artifactory')][string]$Service = 'lab-status',
    [string]$Config = (Join-Path $PSScriptRoot 'bundles-https\client\config.json')
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = (Get-Command python -ErrorAction Stop).Source }
if (-not (Test-Path -LiteralPath $Config)) { throw 'Pacote client nao encontrado.' }
& $pythonPath (Join-Path $PSScriptRoot 'https_poc.py') $Mode.ToLowerInvariant() --config $Config --service $Service
exit $LASTEXITCODE
