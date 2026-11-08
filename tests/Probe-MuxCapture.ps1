$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$report=[ordered]@{Started=[DateTime]::UtcNow.ToString('o');Error=$null}
$trace=Join-Path $PSScriptRoot 'mux-handshake.etl'
$pcap=Join-Path $PSScriptRoot 'mux-handshake.pcapng'
$python=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314\python.exe'
$helper=Join-Path $PSScriptRoot 'Probe-MuxHandshake.py'
$filters=@();$started=$false;$fixture=$null
try {
    $status=@(& pktmon status 2>&1);$report.Status=$status -join "`n"
    if($LASTEXITCODE -ne 0 -or $report.Status -match '\u6b63\u5728\u8fd0\u884c|Running'){throw 'Pktmon is unavailable or already running; no capture started'}
    $previous=@(& pktmon filter list 2>&1);$report.Filters=$previous -join "`n"
    if($LASTEXITCODE -ne 0 -or $report.Filters -notmatch '\u6ca1\u6709|\u672a.*\u7b5b\u9009|(?m)^\s*\u65e0\s*$|No filters|No packet filters'){throw 'Existing/unknown filters; no capture started'}
    $info=[Diagnostics.ProcessStartInfo]::new($python,'"'+$helper+'"')
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardError=$true
    $fixture=[Diagnostics.Process]::Start($info)
    $ready=$fixture.StandardOutput.ReadLineAsync();if(-not $ready.Wait(5000)){throw 'Fixture preparation timeout'}
    if(-not $ready.Result){throw ('Fixture failed: '+$fixture.StandardError.ReadToEnd())}
    $prepared=$ready.Result|ConvertFrom-Json;$report.Prepared=$prepared
    foreach($target in $prepared.targets){$name='SafeDetach-'+[Guid]::NewGuid().ToString('N');& pktmon filter add $name -i 127.0.0.1 -t TCP -p $target.port 27015 | Out-Null;if($LASTEXITCODE -ne 0){throw 'Cannot add test filter'};$filters+=$name}
    & pktmon start --capture --pkt-size 1024 --file-size 1 --file-name $trace | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Cannot start test capture'};$started=$true
    $fixture.StandardInput.WriteLine('continue')
    $output=$fixture.StandardOutput.ReadToEndAsync();if(-not $fixture.WaitForExit(10000)){$fixture.Kill();throw 'Fixture timeout'}
    $report.Fixture=$output.Result;if($fixture.ExitCode -ne 0){throw ('Fixture failed: '+$fixture.StandardError.ReadToEnd())}
    & pktmon stop | Out-Null;$started=$false
    & pktmon etl2pcap $trace --out $pcap | Out-Null;if($LASTEXITCODE -ne 0){throw 'Cannot convert test trace'}
    $analysis=& $python $helper inspect $pcap;if($LASTEXITCODE -ne 0){throw 'Capture parser failed'};$report.Observation=$analysis|ConvertFrom-Json
}catch{$report.Error=$_.Exception.Message}
finally {
    if($started){& pktmon stop | Out-Null}
    foreach($name in $filters){& pktmon filter remove $name | Out-Null}
    if($fixture){if(-not $fixture.HasExited){$fixture.Kill()};$fixture.WaitForExit();$fixture.Dispose()}
    foreach($file in @($trace,$pcap)){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
    $report.Completed=[DateTime]::UtcNow.ToString('o')
    $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'mux-capture-report.json') -Encoding UTF8
}

