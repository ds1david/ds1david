[CmdletBinding()]
param(
    [ValidateSet('Test','Lab','Check','Agent')][string]$Mode = 'Test',
    [ValidateSet('lab-status','lab-catalog','lab-echo','gitlab','artifactory')][string]$Service = 'lab-status',
    [string]$Config = (Join-Path $PSScriptRoot 'bundles-https\agent\config.json')
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython) {
    $pythonPath = $venvPython
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { throw 'Python aprovado nao encontrado. Instale-o pelo canal corporativo.' }
    $pythonPath = $pythonCommand.Source
}
if ($Mode -eq 'Lab') {
    & $pythonPath (Join-Path $PSScriptRoot 'poc.py') lab
    exit $LASTEXITCODE
}
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw 'Falta bundles-https\agent\config.json. Receba somente o pacote agent da estacao de emissao.'
}
$resolvedConfig = (Resolve-Path -LiteralPath $Config).Path
$settings = Get-Content -LiteralPath $resolvedConfig -Raw | ConvertFrom-Json
$configRoot = Split-Path -Parent $resolvedConfig
foreach ($field in @('tls_ca','signing_key','gateway_public')) {
    $requiredFile = Join-Path $configRoot $settings.$field
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) { throw "Arquivo necessario ausente: $field" }
}
& $pythonPath -c 'import jwt; import cryptography' 2>$null
if ($LASTEXITCODE -ne 0) {
    throw 'Dependencias ausentes. Instale requirements-https.txt pelo repositorio de pacotes aprovado; o launcher nao instala nada.'
}
$launcher = Join-Path $PSScriptRoot 'https_poc.py'
if ($Mode -eq 'Check') {
    & $pythonPath $launcher check --config $resolvedConfig --service $Service
    exit $LASTEXITCODE
}
if ($Mode -eq 'Agent') {
    & $pythonPath $launcher agent --config $resolvedConfig --service $Service
    exit $LASTEXITCODE
}
# Default: validate the authenticated endpoint and run fixtures and agent
# inside one foreground Python process. No background service is installed.
& $pythonPath $launcher check --config $resolvedConfig --service $Service
if ($LASTEXITCODE -ne 0) { throw 'Check falhou. Corrija o diagnostico antes de iniciar o agente.' }
if (-not $Service.StartsWith('lab-')) {
    throw 'Modo Test e exclusivo de laboratorio. Servicos reais exigem configuracao e autorizacao; use Agent depois da homologacao.'
}
Write-Host 'Iniciando laboratorio e agente. Deixe este terminal aberto; Ctrl+C encerra o teste.'
& $pythonPath $launcher agent --config $resolvedConfig --service $Service --lab
exit $LASTEXITCODE
