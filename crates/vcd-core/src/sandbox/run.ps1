$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$desktop = Join-Path $env:USERPROFILE 'Desktop'
$out = Join-Path $desktop 'out'
$payload = Join-Path $desktop 'payload'
$droppedDir = Join-Path $out 'dropped'
New-Item -ItemType Directory -Force -Path $droppedDir | Out-Null

$duration = 30
$durationFile = Join-Path $out 'duration.txt'
if (Test-Path $durationFile) {
    $parsed = 0
    if ([int]::TryParse((Get-Content $durationFile -Raw).Trim(), [ref]$parsed) -and $parsed -gt 0 -and $parsed -le 300) {
        $duration = $parsed
    }
}

$state = [ordered]@{
    executed         = $false
    unsupported      = $null
    error            = $null
    started_at       = (Get-Date).ToString('o')
    finished_at      = $null
    finished         = $false
    duration_seconds = $duration
    sample           = $null
    sample_pid       = $null
    sample_exit_ms   = $null
    sample_exit_code = $null
    defender_disabled = $false
    processes        = @()
    connections      = @()
    dns              = @()
    files_created    = @()
    files_modified   = @()
    registry_changed = @()
}

function Save-State {
    $state.finished_at = (Get-Date).ToString('o')
    try {
        $json = $state | ConvertTo-Json -Depth 8
        $tmp = Join-Path $out 'result.tmp'
        [IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Force -Path $tmp -Destination (Join-Path $out 'result.json')
    } catch { }
}

function Snapshot-Files {
    $map = @{}
    foreach ($root in @($env:USERPROFILE, 'C:\Users\Public', 'C:\Windows\Temp')) {
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notlike "$out*" -and $_.FullName -notlike "$payload*" } |
            ForEach-Object { $map[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }
    }
    return $map
}

function Snapshot-Registry {
    $map = @{}
    foreach ($key in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        $item = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        foreach ($name in $item.GetValueNames()) { $map["$key\$name"] = "$($item.GetValue($name))" }
    }
    return $map
}

function Clip([string]$text, [int]$max) {
    if ($null -eq $text) { return $null }
    if ($text.Length -le $max) { return $text }
    return $text.Substring(0, $max) + '...'
}

# CreateProcess, not ShellExecute: an unsigned executable started through the
# shell is held by SmartScreen, which nobody can answer inside the sandbox, and
# the sample then never runs a single instruction.
function Start-Sample([string]$file, [string[]]$arguments, [string]$workingDirectory) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $file
    if ($arguments.Count -gt 0) { $info.Arguments = ($arguments -join ' ') }
    $info.WorkingDirectory = $workingDirectory
    $info.UseShellExecute = $false
    return [System.Diagnostics.Process]::Start($info)
}

# Everything alive before the payload starts is background noise.
$initialPids = @{}
foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $initialPids[$process.ProcessId] = $true
}

# The initial state is written before anything that can block, so a Defender
# provider that stalls still leaves an identifiable run behind.
Save-State | Out-Null

# The guest is disposable and never touches the host: stop its real-time
# protection so a sample is not killed before it can act. Reported as a fact
# only when the setting actually took effect.
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $state.defender_disabled = -not $defender.RealTimeProtectionEnabled
} catch {
    $state.defender_disabled = $false
}

$beforeFiles = Snapshot-Files
$beforeRegistry = Snapshot-Registry
Save-State | Out-Null

$sample = Get-ChildItem -LiteralPath $payload -File | Select-Object -First 1
if ($null -eq $sample) {
    $state.error = 'no sample in payload'
    $state.finished = $true
    Save-State | Out-Null
    Start-Sleep -Seconds 1
    Stop-Computer -Force
    exit
}

$state.sample = $sample.Name
$extension = $sample.Extension.ToLowerInvariant()
$sampleProcess = $null
$sampleStarted = Get-Date

try {
    switch ($extension) {
        { $_ -in '.exe', '.scr', '.com', '.pif', '.cpl' } {
            $sampleProcess = Start-Sample $sample.FullName @() $payload
            $state.executed = $true
        }
        '.msi' {
            $sampleProcess = Start-Sample "$env:WINDIR\System32\msiexec.exe" @('/i', "`"$($sample.FullName)`"") $payload
            $state.executed = $true
        }
        { $_ -in '.bat', '.cmd' } {
            $sampleProcess = Start-Sample "$env:WINDIR\System32\cmd.exe" @('/c', "`"$($sample.FullName)`"") $payload
            $state.executed = $true
        }
        '.ps1' {
            $sampleProcess = Start-Sample "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($sample.FullName)`"") $payload
            $state.executed = $true
        }
        { $_ -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta' } {
            $sampleProcess = Start-Sample "$env:WINDIR\System32\wscript.exe" @("`"$($sample.FullName)`"") $payload
            $state.executed = $true
        }
        default { $state.unsupported = $extension }
    }
} catch {
    $state.error = $_.Exception.Message
}

# The sample is always in its own report, even when it exits before the first
# poll: "nothing observed" must not mean "nothing was started".
if ($null -ne $sampleProcess) {
    $state.sample_pid = $sampleProcess.Id
    $state.processes += [ordered]@{
        pid     = $sampleProcess.Id
        parent  = $PID
        name    = $sampleProcess.ProcessName
        path    = Clip $sample.FullName 260
        command = Clip $sample.FullName 300
    }
}

$knownConnections = @{}
$deadline = (Get-Date).AddSeconds($duration)
$lastSave = Get-Date

while ((Get-Date) -lt $deadline) {
    if ($null -ne $sampleProcess -and $null -eq $state.sample_exit_ms -and $sampleProcess.HasExited) {
        $state.sample_exit_ms = [int]((Get-Date) - $sampleStarted).TotalMilliseconds
        $state.sample_exit_code = $sampleProcess.ExitCode
    }

    if ($state.processes.Count -lt 250) {
        foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
            if ($initialPids.ContainsKey($process.ProcessId)) { continue }
            if ($null -ne ($state.processes | Where-Object { $_.pid -eq $process.ProcessId } | Select-Object -First 1)) { continue }

            $state.processes += [ordered]@{
                pid     = $process.ProcessId
                parent  = $process.ParentProcessId
                name    = $process.Name
                path    = Clip $process.ExecutablePath 260
                command = Clip $process.CommandLine 300
            }
        }
    }

    foreach ($connection in Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -in 'Established', 'SynSent' }) {
        $owner = $connection.OwningProcess
        # Only connections owned by a process this run started; otherwise the
        # sandbox's own telemetry is the whole list and the sample's traffic
        # cannot be told from the system's.
        if (-not ($state.processes | Where-Object { $_.pid -eq $owner } | Select-Object -First 1)) { continue }

        $key = "$($connection.RemoteAddress):$($connection.RemotePort)-$owner"
        if (-not $knownConnections.ContainsKey($key)) {
            $knownConnections[$key] = $true
            $state.connections += [ordered]@{
                remote = "$($connection.RemoteAddress):$($connection.RemotePort)"
                pid    = $connection.OwningProcess
                state  = "$($connection.State)"
            }
        }
    }

    if (((Get-Date) - $lastSave).TotalSeconds -ge 2) {
        Save-State | Out-Null
        $lastSave = Get-Date
    }

    Start-Sleep -Milliseconds 250
}

$state.dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Entry -Unique | Select-Object -First 50)

$afterFiles = Snapshot-Files
$copied = 0
foreach ($path in $afterFiles.Keys) {
    if ($beforeFiles.ContainsKey($path)) {
        if ($beforeFiles[$path] -ne $afterFiles[$path]) {
            $state.files_modified += $path
        }
        continue
    }

    $state.files_created += $path
    if ($copied -lt 10) {
        $info = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($info -and $info.Length -le 5MB) {
            Copy-Item -LiteralPath $path -Destination (Join-Path $droppedDir ('{0:D2}_{1}' -f $copied, $info.Name)) -ErrorAction SilentlyContinue
            $copied++
        }
    }
}

$afterRegistry = Snapshot-Registry
foreach ($key in $afterRegistry.Keys) {
    if (-not $beforeRegistry.ContainsKey($key) -or $beforeRegistry[$key] -ne $afterRegistry[$key]) {
        $state.registry_changed += "$key = $($afterRegistry[$key])"
    }
}

$state.finished = $true
Save-State | Out-Null
Start-Sleep -Seconds 2
Stop-Computer -Force
