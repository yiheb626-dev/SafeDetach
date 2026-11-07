@echo off
setlocal
set "SAFEDETACH_DIAGNOSTIC=%~dp0tests\Probe-Broker.ps1"
echo SafeDetach phone diagnostic
echo Please approve the Windows administrator prompt.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "try { $arguments = '-NoProfile -ExecutionPolicy Bypass -File ' + [char]34 + $env:SAFEDETACH_DIAGNOSTIC + [char]34; $job = Start-Process -FilePath ($env:WINDIR + '\System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -ArgumentList $arguments -PassThru -Wait; exit $job.ExitCode } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (
 echo Diagnostic could not start. Return to the chat with this message.
) else (
 echo Finished. Return to the chat so the report can be checked.
)
pause
endlocal
