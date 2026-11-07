$ErrorActionPreference = 'Stop'
$traceName = 'SafeDetachBrokerProbe-' + [Guid]::NewGuid().ToString('N')
$traceFile = Join-Path $PSScriptRoot 'broker-probe.etl'
$fixtureFile = Join-Path $PSScriptRoot 'PortableConnection.exe'
$reportFile = Join-Path $PSScriptRoot 'broker-probe-report.json'
$providerFile = Join-Path $PSScriptRoot 'broker-providers.txt'
$started = $false
$report = [ordered]@{ Version=2; Started = [DateTime]::UtcNow.ToString('o'); Events = @(); Error = $null }
try {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe /platform:x64 "/out:$fixtureFile" (Join-Path $PSScriptRoot 'PortableConnection.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed' }
    @('{64FB8D23-F0B6-5D2D-B1F6-488303C1761F} 0xffffffffffffffff 5','{31569DCF-9C6F-4B8E-843A-B7C1CC7FFCBA} 0xffffffffffffffff 5','{2E35AAEB-857F-4BEB-A418-2E6C0E54D988} 0xffffffffffffffff 5') | Set-Content -LiteralPath $providerFile -Encoding ASCII
    $result = & logman create trace $traceName -pf $providerFile -o $traceFile -ets 2>&1
    if ($LASTEXITCODE -ne 0) {throw ($result -join "`n")}
    $started = $true
    $report.TraceConfiguration = @(& logman query $traceName -ets 2>&1 | ForEach-Object {"$_"})
    $env:SAFEDETACH_FIXTURE_HOLD_MS = '1500'
    $info = [Diagnostics.ProcessStartInfo]::new($fixtureFile)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $read = $process.StandardOutput.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Fixture timed out' }
        $report.Fixture = $read.Result
        $report.FixtureExitCode = $process.ExitCode
    } finally { $process.Dispose() }
    & logman stop $traceName -ets | Out-Null
    $started = $false
    $events = @(Get-WinEvent -Path $traceFile -Oldest -ErrorAction SilentlyContinue)
    $report.TotalEvents = $events.Count
    $report.ProviderCounts = @($events | Group-Object ProviderName | Select-Object Name,Count)
    $report.Events = @($events | Where-Object {$_.ProviderName -like 'Microsoft-Windows-WPD*' -or $_.ProviderName -eq 'Microsoft-Windows-Devices-AccessBroker' -or $_.ProviderName -eq 'Microsoft-Windows-DriverFrameworks-UserMode'} | Select-Object -First 300 | ForEach-Object {
        $eventXml = [xml]$_.ToXml()
        $fields = @($eventXml.Event.EventData.Data | ForEach-Object {
            $value = $_.'#text'
            if ($value -and $value.Length -gt 1024) { $value = '[payload omitted]' }
            [ordered]@{Name=$_.Name;Value=$value}
        })
        [ordered]@{Provider=$_.ProviderName;Id=$_.Id;Time=$_.TimeCreated.ToUniversalTime().ToString('o');Process=$_.ProcessId;Data=$fields}
    })
    if ($report.Events.Count -eq 0) {throw 'No matching device events were captured; diagnostic is inconclusive.'}
} catch { $report.Error = $_.Exception.Message }
finally {
    if ($started) { & logman stop $traceName -ets | Out-Null }
    foreach ($file in @($traceFile,$fixtureFile,$providerFile)) {if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}}
    $report.Completed = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportFile -Encoding UTF8
    if($report.Error){Write-Host $report.Error;exit 1}
}
