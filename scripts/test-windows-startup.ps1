param(
    [Parameter(Mandatory)]
    [string] $Archive
)

$ErrorActionPreference = 'Stop'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$packageDir = Join-Path $workDir 'Moonlight'
$stdout = Join-Path $workDir 'stdout.log'
$stderr = Join-Path $workDir 'stderr.log'
$process = $null

try {
    Expand-Archive -LiteralPath $Archive -DestinationPath $packageDir
    $process = Start-Process -FilePath (Join-Path $packageDir 'Moonlight.exe') `
        -WorkingDirectory $packageDir -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
        if ($process.HasExited) {
            throw ('Moonlight exited before showing its main window (0x{0:X8})' -f $process.ExitCode)
        }
    } until (($process.MainWindowTitle -eq 'Moonlight V+ for PC' -and $process.Responding) -or
             [DateTime]::UtcNow -ge $deadline)

    if ($process.MainWindowTitle -ne 'Moonlight V+ for PC' -or !$process.Responding) {
        throw 'Moonlight did not show a responsive main window within 45 seconds'
    }
    Start-Sleep -Seconds 3
    $process.Refresh()
    if ($process.HasExited) {
        throw ('Moonlight exited after showing its main window (0x{0:X8})' -f $process.ExitCode)
    }
    if ($process.MainWindowTitle -ne 'Moonlight V+ for PC' -or !$process.Responding) {
        throw 'Moonlight main window stopped responding after launch'
    }
    Write-Output 'Moonlight V+ main window opened and responded'
} finally {
    if ($null -ne $process -and !$process.HasExited) {
        if (!$process.CloseMainWindow() -or !$process.WaitForExit(5000)) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
    foreach ($log in @($stdout, $stderr)) {
        if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log -Tail 60
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
