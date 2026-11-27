param(
    [Parameter(Mandatory = $true)][string]$StartExe,
    [Parameter(Mandatory = $true)][string]$Box,
    [Parameter(Mandatory = $true)][string]$Sample,
    [Parameter(Mandatory = $true)][int]$Seconds,
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][string]$BoxRoot,
    [Parameter(Mandatory = $true)][string]$CopyTo
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $CopyTo | Out-Null

$state = [ordered]@{
    executed         = $false
    unsupported      = $null
    error            = $null
    finished         = $false
    started_at       = (Get-Date).ToString('o')
    finished_at      = $null
    duration_seconds = $Seconds
    sample           = (Split-Path $Sample -Leaf)
    sample_exit_ms   = $null
    sample_exit_code = $null
    processes        = @()
    connections      = @()
    dns              = @()
    files_created    = @()
    files_modified   = @()
    registry_changed = @()
}

$beforePids = @{}
foreach ($process in Get-CimInstance Win32_Process) {
    $beforePids[[int]$process.ProcessId] = $true
}

$beforeFiles = @{}
if (Test-Path $BoxRoot) {
    Get-ChildItem -LiteralPath $BoxRoot -Recurse -File | ForEach-Object {
        $beforeFiles[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
    }
}

$sampleStarted = Get-Date
$samplePid = $null
# `-ArgumentList` joins its elements with spaces, so the sample path has to be
# quoted here or a profile like "C:\Users\John Smith" is split apart and
# Start.exe never finds the file.
try {
    Start-Process -FilePath $StartExe -ArgumentList @("/box:$Box", '/silent', "`"$Sample`"") | Out-Null
} catch {
    $state.error = $_.Exception.Message
}

# `executed` means the sample really started inside the box, not that Start.exe
# was spawned. It cannot be an image match: `.bat`, `.ps1` and `.vbs` run through
# an interpreter, so the sample appears in the command line instead.
$launchDeadline = (Get-Date).AddSeconds(5)
while (-not $state.executed -and (Get-Date) -lt $launchDeadline) {
    foreach ($process in Get-CimInstance Win32_Process) {
        if ($beforePids.ContainsKey([int]$process.ProcessId)) { continue }
        $image = $process.ExecutablePath
        $command = $process.CommandLine
        if ($image -eq $Sample -or ($command -and $command.Contains($Sample))) {
            $state.executed = $true
            $samplePid = [int]$process.ProcessId
            break
        }
    }
    if (-not $state.executed) { Start-Sleep -Milliseconds 200 }
}
if (-not $state.executed -and -not $state.error) {
    $state.error = 'the sample did not start inside the box'
}

$seen = @{}
$seenConnections = @{}
$deadline = (Get-Date).AddSeconds($Seconds)
$lastSave = Get-Date

function Save-State([bool]$final) {
    $state.finished = $final
    $state.finished_at = (Get-Date).ToString('o')
    try {
        [IO.File]::WriteAllText($Out, ($state | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding $false))
    } catch { }
}

while ((Get-Date) -lt $deadline) {
    if ($null -ne $samplePid -and $null -eq $state.sample_exit_ms -and
        $null -eq (Get-Process -Id $samplePid -ErrorAction SilentlyContinue)) {
        $state.sample_exit_ms = [int]((Get-Date) - $sampleStarted).TotalMilliseconds
    }

    foreach ($process in Get-CimInstance Win32_Process) {
        $processId = [int]$process.ProcessId
        if ($beforePids.ContainsKey($processId)) { continue }
        if ($seen.ContainsKey($processId)) { continue }
        $seen[$processId] = $true
        $state.processes += [ordered]@{
            pid     = $processId
            parent  = [int]$process.ParentProcessId
            name    = $process.Name
            path    = $process.ExecutablePath
            command = $process.CommandLine
        }
    }

    foreach ($connection in Get-NetTCPConnection | Where-Object { $_.State -in 'Established', 'SynSent' }) {
        $key = "$($connection.RemoteAddress):$($connection.RemotePort)-$($connection.OwningProcess)"
        if (-not $seenConnections.ContainsKey($key)) {
            $seenConnections[$key] = $true
            $state.connections += [ordered]@{
                remote = "$($connection.RemoteAddress):$($connection.RemotePort)"
                pid    = [int]$connection.OwningProcess
                state  = "$($connection.State)"
            }
        }
    }

    if (((Get-Date) - $lastSave).TotalSeconds -ge 2) {
        Save-State $false
        $lastSave = Get-Date
    }

    Start-Sleep -Milliseconds 250
}

& $StartExe "/box:$Box" /terminate | Out-Null
Start-Sleep -Seconds 2

# Tie the report to the sample: keep its process and descendants, drop the rest.
$sampleName = Split-Path $Sample -Leaf
$inScope = @{}
foreach ($process in $state.processes) {
    if (($process.command -and $process.command -like "*$sampleName*") -or ($process.path -eq $Sample)) {
        $inScope[[int]$process.pid] = $true
    }
}

$changed = $true
while ($changed) {
    $changed = $false
    foreach ($process in $state.processes) {
        $processId = [int]$process.pid
        if ($inScope.ContainsKey($processId)) { continue }
        if ($inScope.ContainsKey([int]$process.parent)) {
            $inScope[$processId] = $true
            $changed = $true
        }
    }
}

$state.processes = @($state.processes | Where-Object { $inScope.ContainsKey([int]$_.pid) -and $_.name -ne 'Start.exe' })
$state.connections = @($state.connections | Where-Object { $inScope.ContainsKey([int]$_.pid) })

$afterFiles = @{}
if (Test-Path $BoxRoot) {
    Get-ChildItem -LiteralPath $BoxRoot -Recurse -File | ForEach-Object {
        $afterFiles[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
    }
}

$copied = 0
foreach ($path in $afterFiles.Keys) {
    if ($path -like '*\RegHive' -or $path -like '*\DONT-USE.TXT') { continue }

    if ($beforeFiles.ContainsKey($path)) {
        if ($beforeFiles[$path] -ne $afterFiles[$path]) { $state.files_modified += $path }
        continue
    }

    $state.files_created += $path
    if ($copied -lt 10) {
        $info = Get-Item -LiteralPath $path
        if ($info -and $info.Length -le 5MB) {
            Copy-Item -LiteralPath $path -Destination (Join-Path $CopyTo ('{0:D2}_{1}' -f $copied, $info.Name))
            $copied++
        }
    }
}

$state.dns = @(Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique | Select-Object -First 50)
Save-State $true
