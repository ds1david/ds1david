[CmdletBinding()]
param(
    [ValidateSet('Test','Lab','Check','Agent','Homologation','Status','Stop')][string]$Mode = 'Test',
    [ValidateSet('lab-status','lab-catalog','lab-echo','gitlab','artifactory','homologation')][string]$Service = 'lab-status',
    [string]$Config = '',
    [switch]$Foreground,
    [string]$RuntimeDirectory = ''
)
$ErrorActionPreference = 'Stop'
if (-not $Config) { $Config = Join-Path $PSScriptRoot 'bundles-https\agent\config.json' }
if (-not $RuntimeDirectory) { $RuntimeDirectory = Join-Path $env:LOCALAPPDATA 'secure-gateway\agent' }
Set-Location -LiteralPath $PSScriptRoot
$runtimePath = [System.IO.Path]::GetFullPath($RuntimeDirectory)
$recordPath = Join-Path $runtimePath 'agent.json'
$readyPath = Join-Path $runtimePath 'ready.json'
$stopPath = Join-Path $runtimePath 'stop.request'
function Get-ManagedAgent {
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) { return $null }
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    $running = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $running) { return $null }
    if ($running.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.start_ticks -or $running.Path -ne $record.executable) {
        throw 'O PID registrado pertence a outro processo. Nao sera encerrado.'
    }
    return [pscustomobject]@{ Process = $running; Record = $record }
}
if ($Mode -in @('Status','Stop')) {
    $managed = Get-ManagedAgent
    if ($null -eq $managed) {
        Write-Output '{"event":"agent_not_running"}'
        exit 0
    }
    if ($Mode -eq 'Stop') {
        if ($managed.Record.stop_file -eq $stopPath) {
            Set-Content -LiteralPath $stopPath -Value 'stop' -Encoding ASCII
            $stopDeadline = (Get-Date).AddSeconds(12)
            while (-not $managed.Process.HasExited -and (Get-Date) -lt $stopDeadline) { Start-Sleep -Milliseconds 250 }
        }
        if (-not $managed.Process.HasExited) {
            $verified = Get-ManagedAgent
            if ($null -ne $verified) { Stop-Process -Id $verified.Process.Id -ErrorAction Stop }
        }
        Remove-Item -LiteralPath $recordPath -Force
        if (Test-Path -LiteralPath $readyPath) { Remove-Item -LiteralPath $readyPath -Force }
        if (Test-Path -LiteralPath $stopPath) { Remove-Item -LiteralPath $stopPath -Force }
        Write-Output '{"event":"agent_stopped"}'
    } else {
        $managed.Record | ConvertTo-Json
    }
    exit 0
}
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
if ($settings.operation_mode -eq 'homologation') {
    if (-not $PSBoundParameters.ContainsKey('Mode')) { $Mode = 'Homologation' }
    if (-not $PSBoundParameters.ContainsKey('Service')) { $Service = 'homologation' }
}
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
    $checkMode = 'check'
    if ($Service -eq 'homologation') { $checkMode = 'preflight' }
    & $pythonPath $launcher $checkMode --config $resolvedConfig --service $Service
    exit $LASTEXITCODE
}
if ($Mode -in @('Agent','Homologation')) {
    if ($Mode -eq 'Homologation') { $Service = 'homologation' }
    $managed = Get-ManagedAgent
    if ($null -ne $managed) {
        $managed.Record | ConvertTo-Json
        exit 0
    }
    & $pythonPath $launcher preflight --config $resolvedConfig --service $Service
    if ($LASTEXITCODE -ne 0) { throw 'Preflight falhou. Nenhum agente foi iniciado. Confira os eventos acima.' }
    if ($Foreground) {
        & $pythonPath $launcher agent --config $resolvedConfig --service $Service --preflight
        exit $LASTEXITCODE
    }
    New-Item -ItemType Directory -Force -Path $runtimePath | Out-Null
    if (Test-Path -LiteralPath $readyPath) { Remove-Item -LiteralPath $readyPath -Force }
    if (Test-Path -LiteralPath $stopPath) { Remove-Item -LiteralPath $stopPath -Force }
    $runId = [Guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $runtimePath ("agent-$runId.log")
    $stderrPath = Join-Path $runtimePath ("agent-$runId.stderr.log")
    $arguments = '"' + $launcher + '" agent --config "' + $resolvedConfig + '" --service ' + $Service + ' --preflight --ready-file "' + $readyPath + '" --stop-file "' + $stopPath + '"'
    $launchProcess = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    $deadline = (Get-Date).AddSeconds(45)
    while (-not (Test-Path -LiteralPath $readyPath)) {
        if ($launchProcess.HasExited -or (Get-Date) -ge $deadline) {
            if (-not $launchProcess.HasExited) {
                try { & taskkill.exe /PID $launchProcess.Id /T /F 2>$null | Out-Null } catch {}
            }
            throw "Agente nao ficou pronto; veja $stdoutPath e $stderrPath. Nenhum servico de inicializacao foi instalado."
        }
        Start-Sleep -Milliseconds 250
    }
    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    # Track the real Python PID, not the virtualenv redirector parent.
    $agentProcess = Get-Process -Id ([int]$ready.pid) -ErrorAction Stop
    $record = [ordered]@{ event='agent_running'; pid=$agentProcess.Id; start_ticks=$agentProcess.StartTime.ToUniversalTime().Ticks.ToString(); executable=$agentProcess.Path; service=$Service; config=$resolvedConfig; stdout=$stdoutPath; stderr=$stderrPath; stop_file=$stopPath }
    $record | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding UTF8
    $record | ConvertTo-Json
    exit 0
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
