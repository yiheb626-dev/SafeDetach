$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$fixtureFile=Join-Path $PSScriptRoot 'PortableConnection.exe'
$probeFile=Join-Path $PSScriptRoot 'NativeProbe.exe'
$fixture=$null
try {
    & $compiler /nologo /target:exe /platform:x64 "/out:$fixtureFile" (Join-Path $PSScriptRoot 'PortableConnection.cs')
    if($LASTEXITCODE -ne 0){throw 'Fixture build failed'}
    & $compiler /nologo /target:exe /platform:x64 "/out:$probeFile" (Join-Path $PSScriptRoot 'NativeProbe.cs') (Join-Path $PSScriptRoot '..\src\HandleScanner.cs') (Join-Path $PSScriptRoot '..\src\PortableProtocol.cs')
    if($LASTEXITCODE -ne 0){throw 'Probe build failed'}
    $info=[Diagnostics.ProcessStartInfo]::new($fixtureFile)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardInput=$true
    $info.EnvironmentVariables['SAFEDETACH_FIXTURE_PHASES']='1'
    $fixture=[Diagnostics.Process]::Start($info)
    foreach($phase in @('BEFORE','READY','CLOSED')) {
        $line=$fixture.StandardOutput.ReadLineAsync()
        if(-not $line.Wait(10000)){throw 'Phase startup timeout'}
        if($line.Result -notlike ($phase+'*')){throw ('Unexpected phase: '+$line.Result)}
        Write-Output $line.Result
        $pi=[Diagnostics.ProcessStartInfo]::new($probeFile,[string]$fixture.Id)
        $pi.UseShellExecute=$false;$pi.CreateNoWindow=$true;$pi.RedirectStandardOutput=$true
        $probe=[Diagnostics.Process]::Start($pi)
        try {
            $read=$probe.StandardOutput.ReadToEndAsync()
            if(-not $probe.WaitForExit(10000)){$probe.Kill();$probe.WaitForExit();throw 'Probe timeout'}
            $read.Result -split "`n" | Where-Object {$_ -match '^DEBUG|^DONE'}
        } finally {$probe.Dispose()}
        $fixture.StandardInput.WriteLine('continue')
    }
    if(-not $fixture.WaitForExit(5000)){throw 'Fixture exit timeout'}
    if($fixture.ExitCode -ne 0){throw 'Fixture failed'}
} finally {
    if($fixture){if(-not $fixture.HasExited){$fixture.Kill()};$fixture.WaitForExit();$fixture.Dispose()}
    foreach($file in @($fixtureFile,$probeFile)){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
}

