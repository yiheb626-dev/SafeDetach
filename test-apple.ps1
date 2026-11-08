param([switch]$Hardware,[switch]$RetryUi,[string]$AppPath)
$ErrorActionPreference='Stop'
$binary=Join-Path $PSScriptRoot 'tests\AppleConnections.exe'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$appCopy=Join-Path $PSScriptRoot 'tests\SafeDetach.exe'
$ownsCopy=$false
try {
    if($AppPath){
        if(Test-Path -LiteralPath $appCopy){throw 'Temporary app path already exists; refusing to overwrite'}
        $app=(Resolve-Path -LiteralPath $AppPath).Path
        Copy-Item -LiteralPath $app -Destination $appCopy
        $ownsCopy=$true
        $sources=@('/reference:'+$appCopy)
    }else{$sources=Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName}
    & $compiler /nologo /target:exe /platform:x64 /main:AppleConnections /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$binary" $sources (Join-Path $PSScriptRoot 'tests\AppleConnections.cs')
    if($LASTEXITCODE -ne 0){throw 'Apple test compilation failed'}
    if($Hardware){& $binary --hardware}elseif($RetryUi){& $binary --retry-ui}else{& $binary}
    if($LASTEXITCODE -ne 0){throw 'Apple connection tests failed'}
} finally {if(Test-Path -LiteralPath $binary){Remove-Item -LiteralPath $binary};if($ownsCopy){Remove-Item -LiteralPath $appCopy}}
