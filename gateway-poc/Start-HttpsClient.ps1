[CmdletBinding()]
param(
    [ValidateSet('Check','Query','Forward','Proxy')][string]$Mode = 'Query',
    [ValidateSet('lab-status','lab-catalog','lab-echo','gitlab','artifactory','homologation')][string]$Service = 'lab-status',
    [string]$Config = ''
)
$ErrorActionPreference = 'Stop'
if (-not $Config) { $Config = Join-Path $PSScriptRoot 'bundles-https\client\config.json' }
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = (Get-Command python -ErrorAction Stop).Source }
if (-not (Test-Path -LiteralPath $Config)) { throw 'Pacote client nao encontrado.' }
$settings = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if ($settings.operation_mode -eq 'homologation') {
    if (-not $PSBoundParameters.ContainsKey('Mode')) { $Mode = 'Proxy' }
    if (-not $PSBoundParameters.ContainsKey('Service')) { $Service = 'homologation' }
}
& $pythonPath (Join-Path $PSScriptRoot 'https_poc.py') $Mode.ToLowerInvariant() --config $Config --service $Service
exit $LASTEXITCODE
