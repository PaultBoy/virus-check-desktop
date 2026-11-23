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

# Everything alive before the payload starts is background noise.
$initialPids = @{}
foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $initialPids[$process.ProcessId] = $true
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

try {
    switch ($extension) {
        { $_ -in '.exe', '.scr', '.com', '.pif', '.cpl', '.msi' } {
            Start-Process -FilePath $sample.FullName -WorkingDirectory $payload
            $state.executed = $true
        }
        { $_ -in '.bat', '.cmd' } {
            Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/c', "`"$($sample.FullName)`""
            $state.executed = $true
        }
        '.ps1' {
            Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($sample.FullName)`""
            $state.executed = $true
        }
        { $_ -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta' } {
            Start-Process -FilePath "$env:WINDIR\System32\wscript.exe" -ArgumentList "`"$($sample.FullName)`""
            $state.executed = $true
        }
        default { $state.unsupported = $extension }
    }
} catch {
    $state.error = $_.Exception.Message
}

$knownConnections = @{}
$deadline = (Get-Date).AddSeconds($duration)
$lastSave = Get-Date

while ((Get-Date) -lt $deadline) {
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
        $key = "$($connection.RemoteAddress):$($connection.RemotePort)-$($connection.OwningProcess)"
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

    Start-Sleep -Milliseconds 500
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
