param([string]$AppPath)
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$fixtureFile=Join-Path $PSScriptRoot 'tests\PortableConnection.exe'
$app=Join-Path $PSScriptRoot 'tests\Diagnostic.exe'
$ownsApp=-not $AppPath
if($AppPath){$app=(Resolve-Path -LiteralPath $AppPath).Path}
$negative=Join-Path $PSScriptRoot 'tests\PortableNegative.exe'
$fixture=$null
try {
    & $compiler /nologo /target:exe /platform:x64 "/out:$fixtureFile" (Join-Path $PSScriptRoot 'tests\PortableConnection.cs')
    if($LASTEXITCODE -ne 0){throw 'Fixture build failed'}
    $sources=Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName
    if($ownsApp){& $compiler /nologo /target:exe /platform:x64 /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$app" $sources;if($LASTEXITCODE -ne 0){throw 'App build failed'}}
    & $compiler /nologo /target:exe /platform:x64 /main:PortableNegative /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$negative" $sources (Join-Path $PSScriptRoot 'tests\PortableNegative.cs')
    if($LASTEXITCODE -ne 0){throw 'Negative test build failed'}
    $phone=Get-PnpDevice -PresentOnly -Class WPD | Where-Object {$_.FriendlyName -match 'iPhone'} | Select-Object -First 1
    if(-not $phone){throw 'Connect and unlock an iPhone to run this hardware test'}
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($phone.InstanceId))
    $info=[Diagnostics.ProcessStartInfo]::new($fixtureFile)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardInput=$true
    $info.EnvironmentVariables['SAFEDETACH_FIXTURE_PHASES']='1'
    $info.EnvironmentVariables['SAFEDETACH_FIXTURE_INSTANCE']=$phone.InstanceId
    $fixture=[Diagnostics.Process]::Start($info)
    foreach($phase in @('BEFORE','READY','CLOSED')) {
        $line=$fixture.StandardOutput.ReadLineAsync()
        if(-not $line.Wait(10000)){throw 'Phase startup timeout'}
        if($line.Result -notlike ($phase+'*')){throw ('Unexpected phase: '+$line.Result)}
        $pi=[Diagnostics.ProcessStartInfo]::new($app,'--portable '+$encoded)
        $pi.UseShellExecute=$false;$pi.CreateNoWindow=$true;$pi.RedirectStandardOutput=$true
        $probe=[Diagnostics.Process]::Start($pi)
        try {
            $read=$probe.StandardOutput.ReadToEndAsync()
            if(-not $probe.WaitForExit(25000)){$probe.Kill();$probe.WaitForExit();throw 'Scan timeout'}
            $output=$read.Result
            if($probe.ExitCode -ne 0 -or $output -notmatch 'DONE'){throw ('Scan failed: '+$output)}
            $found=$false
            foreach($result in ($output -split "`n")) {$fields=$result.Trim() -split "`t";if($fields.Count -eq 5 -and $fields[0] -eq 'H' -and $fields[1] -eq [string]$fixture.Id){$found=$true}}
            if($found -ne ($phase -eq 'READY')){throw ('Incorrect phone occupancy in phase '+$phase)}
            Write-Output ('PASS: phone connection '+$phase+'; detected='+$found)
        } finally {$probe.Dispose()}
        if($phase -eq 'READY') {
            $ni=[Diagnostics.ProcessStartInfo]::new($negative,$encoded);$ni.UseShellExecute=$false;$ni.CreateNoWindow=$true;$ni.RedirectStandardOutput=$true
            $wrong=[Diagnostics.Process]::Start($ni)
            try {$result=$wrong.StandardOutput.ReadToEndAsync();if(-not $wrong.WaitForExit(25000)){$wrong.Kill();$wrong.WaitForExit();throw 'Negative test timeout'};if($wrong.ExitCode -ne 0 -or $result.Result -notmatch 'DONE' -or $result.Result -match '(?m)^H\t'){throw 'Wrong identity matched a device'};Write-Output 'PASS: different phone identity rejected'}finally{$wrong.Dispose()}
        }
        $fixture.StandardInput.WriteLine('continue')
    }
    if(-not $fixture.WaitForExit(5000)){throw 'Fixture exit timeout'}
    if($fixture.ExitCode -ne 0){throw 'Fixture failed'}
} finally {
    if($fixture){if(-not $fixture.HasExited){$fixture.Kill()};$fixture.WaitForExit();$fixture.Dispose()}
    $temporaryFiles=@($fixtureFile,$negative);if($ownsApp){$temporaryFiles+=$app}
    foreach($file in $temporaryFiles){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
}
