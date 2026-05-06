#Requires -Version 5.1
<#
.SYNOPSIS
    WinOpSec Utility - OpSec, Privacy & System Hardening Toolkit
.DESCRIPTION
    Run locally: powershell -ExecutionPolicy Bypass -File WinOpSec.ps1
#>

$Host.UI.RawUI.WindowTitle = "WinOpSec Utility"
$script:LogFile = "$env:TEMP\WinOpSec_$(Get-Date -Format 'yyyyMMdd_HHmm').log"

# Matrix green color scheme
# Primary   = Green
# Secondary = DarkGreen
# Accent    = White (for highlights)
# Dim       = DarkGray
# Alert     = Yellow
# Danger    = Red

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    "$ts [$Level] $Message" | Out-File -FilePath $script:LogFile -Append
}

function Show-Logo {
    Write-Host ''
    Write-Host ' ______     ____   ___   ____ ___  _____  _______   __' -ForegroundColor Red
    Write-Host '|  ____|   / ___| / _ \ / ___|_ _|| ____||_   _|\ \ / /' -ForegroundColor Red
    Write-Host '| |__      \___ \| | | | |    | | |  _|    | |   \ V / ' -ForegroundColor DarkRed
    Write-Host '|  __|      ___) | |_| | |___ | | | |___   | |    | |  ' -ForegroundColor DarkRed
    Write-Host '|_|        |____/ \___/ \____|___||_____|  |_|    |_|  ' -ForegroundColor Red
    Write-Host ''
    Write-Host '        [ F   S O C I E T Y ]' -ForegroundColor Red
    Write-Host '  W I N O P S E C  //  O P S E C  U T I L I T Y' -ForegroundColor DarkRed
    Write-Host '  OpSec | Privacy | Hardening | Network | SysInfo | Threat Intel' -ForegroundColor Red
    Write-Host ''
}

function Show-Divider {
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkGreen
}

function Show-Banner {
    Clear-Host
    Show-Logo
    Show-Divider
}

function Show-Menu {
    param([string]$Title, [array]$Items)
    Write-Host ""
    Write-Host "  | >> $Title" -ForegroundColor Green
    Show-Divider
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $num  = "  |  [{0}]" -f ($i + 1)
        $name = $Items[$i].Name
        $desc = $Items[$i].Desc
        Write-Host $num -ForegroundColor Green -NoNewline
        Write-Host " $name" -ForegroundColor Red -NoNewline
        Write-Host " // $desc" -ForegroundColor DarkGreen
    }
    Write-Host "  |  [0]" -ForegroundColor DarkGreen -NoNewline
    Write-Host " EXIT / BACK" -ForegroundColor DarkGreen
    Show-Divider
    Write-Host ""
}

function Pause-Screen {
    Write-Host ""
    Write-Host "  [*] Press any key to continue..." -ForegroundColor DarkGreen
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Confirm-Action {
    param([string]$Message)
    Write-Host ""
    Write-Host "  [!] $Message" -ForegroundColor Yellow
    $ans = Read-Host "  [?] Continue? (y/N)"
    return ($ans -match '^[Yy]$')
}

function Test-AdminPrivilege {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  [X] REQUIRES ADMINISTRATOR PRIVILEGES." -ForegroundColor Red
        Write-Host "  [!] Restart PowerShell as Admin and try again." -ForegroundColor Yellow
        Pause-Screen
        return $false
    }
    return $true
}

function Write-OK   { param($m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Info { param($m) Write-Host "  [>>] $m" -ForegroundColor DarkGreen }
function Write-Warn { param($m) Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "  [X]  $m" -ForegroundColor Red }
function Write-Dim  { param($m) Write-Host "       $m" -ForegroundColor DarkGray }

# ============================================================
#  OPSEC / PRIVACY CHECKS
# ============================================================
function Show-ExternalIP {
    Write-Host "`n  [>>] Querying external IP data..." -ForegroundColor DarkGreen
    try {
        $data = Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 8
        Write-Host ""
        Write-Host "  [IP]      " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.ip       -ForegroundColor Green
        Write-Host "  [HOST]    " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.hostname  -ForegroundColor White
        Write-Host "  [CITY]    " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.city      -ForegroundColor White
        Write-Host "  [REGION]  " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.region    -ForegroundColor White
        Write-Host "  [COUNTRY] " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.country   -ForegroundColor White
        Write-Host "  [ORG/ISP] " -NoNewline -ForegroundColor DarkGreen; Write-Host $data.org       -ForegroundColor Yellow
        Write-Log "External IP: $($data.ip) | $($data.org)"
    } catch {
        Write-Err "Could not reach ipinfo.io -- check connection."
    }
    Pause-Screen
}

function Show-DNSLeakTest {
    Write-Host "`n  [>>] DNS server configuration..." -ForegroundColor DarkGreen
    Write-Host ""
    $adapters = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 }
    foreach ($a in $adapters) {
        Write-Host "  [IFACE] $($a.InterfaceAlias)" -ForegroundColor Green
        foreach ($dns in $a.ServerAddresses) {
            $flag = ""
            if ($dns -match "^(8\.8\.|8\.4\.|1\.1\.|1\.0\.)") { $flag = "// Google/Cloudflare (Public)" }
            elseif ($dns -match "^(9\.9\.9\.|149\.112\.)")     { $flag = "// Quad9 (Private DNS)" }
            elseif ($dns -match "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.") { $flag = "// Router/Private" }
            $col = if ($flag) { "Yellow" } else { "DarkGray" }
            Write-Host "    DNS >> $dns $flag" -ForegroundColor $col
        }
        Write-Host ""
    }
    Write-Info "Recommended: 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9)"
    Write-Log "DNS check done"
    Pause-Screen
}

function Show-OpenPorts {
    Write-Host "`n  [>>] Scanning listening ports..." -ForegroundColor DarkGreen
    Write-Host ""
    $conns = Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object -First 30
    Write-Host ("  {0,-8} {1,-25} {2}" -f "PORT","PROCESS","PID") -ForegroundColor Green
    Write-Host ("  " + "-" * 50) -ForegroundColor DarkGreen
    foreach ($c in $conns) {
        try { $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
        catch { $proc = "unknown" }
        $color = if ($c.LocalPort -in @(135,139,445,3389,5985,5986)) { "Red" } else { "White" }
        Write-Host ("  {0,-8} {1,-25} {2}" -f $c.LocalPort, $proc, $c.OwningProcess) -ForegroundColor $color
    }
    Write-Host ""
    Write-Warn "Ports in RED = high-risk attack surfaces"
    Write-Log "Open ports scanned"
    Pause-Screen
}

function Show-ActiveConnections {
    Write-Host "`n  [>>] Active established connections..." -ForegroundColor DarkGreen
    Write-Host ""
    $conns = Get-NetTCPConnection -State Established |
             Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.)" } |
             Sort-Object RemoteAddress
    Write-Host ("  {0,-22} {1,-8} {2,-22} {3}" -f "LOCAL","LPORT","REMOTE","PROCESS") -ForegroundColor Green
    Write-Host ("  " + "-" * 70) -ForegroundColor DarkGreen
    foreach ($c in $conns) {
        try { $proc = (Get-Process -Id $c.OwningProcess -EA SilentlyContinue).ProcessName } catch { $proc = "?" }
        Write-Host ("  {0,-22} {1,-8} {2,-22} {3}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $proc) -ForegroundColor White
    }
    Write-Log "Active connections listed"
    Pause-Screen
}

function Show-ScheduledTasksAudit {
    Write-Host "`n  [>>] Non-Microsoft scheduled tasks..." -ForegroundColor DarkGreen
    Write-Host ""
    $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" })
    if ($tasks.Count -eq 0) {
        Write-OK "No suspicious scheduled tasks found."
    } else {
        Write-Host ("  {0,-40} {1,-15} {2}" -f "TASK","STATE","AUTHOR") -ForegroundColor Green
        Write-Host ("  " + "-" * 75) -ForegroundColor DarkGreen
        foreach ($t in $tasks) {
            $author = try { $t.Principal.UserId } catch { "Unknown" }
            $shortName = if ($t.TaskName.Length -gt 38) { $t.TaskName.Substring(0,37) + "..." } else { $t.TaskName }
            Write-Host ("  {0,-40} {1,-15} {2}" -f $shortName, $t.State, $author) -ForegroundColor Yellow
        }
    }
    Write-Log "Scheduled task audit done"
    Pause-Screen
}

function Show-AutoRunEntries {
    Write-Host "`n  [>>] Autorun registry keys..." -ForegroundColor DarkGreen
    Write-Host ""
    $keys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $found = $false
    foreach ($key in $keys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty $key -EA SilentlyContinue
            $props = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
            if ($props) {
                Write-Host "  [KEY] $key" -ForegroundColor Green
                foreach ($p in $props) {
                    Write-Host "    >> $($p.Name) = $($p.Value)" -ForegroundColor Yellow
                    $found = $true
                }
                Write-Host ""
            }
        }
    }
    if (-not $found) { Write-OK "No entries found in autorun keys." }
    Write-Log "Autorun audit done"
    Pause-Screen
}

# ============================================================
#  SYSTEM HARDENING
# ============================================================
function Disable-Telemetry {
    if (-not (Test-AdminPrivilege)) { return }
    if (-not (Confirm-Action "Disable Windows telemetry and data collection services?")) { return }
    Write-Host "`n  [>>] Killing telemetry..." -ForegroundColor DarkGreen
    $regTweaks = @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0 },
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name="TailoredExperiencesWithDiagnosticDataEnabled"; Value=0 },
        @{ Path="HKCU:\Software\Microsoft\Input\TIPC"; Name="Enabled"; Value=0 }
    )
    foreach ($t in $regTweaks) {
        if (-not (Test-Path $t.Path)) { New-Item -Path $t.Path -Force | Out-Null }
        Set-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -Type DWord -Force
        Write-OK "$($t.Name)"
    }
    foreach ($svc in @("DiagTrack","dmwappushservice","WerSvc")) {
        try {
            Stop-Service $svc -Force -EA SilentlyContinue
            Set-Service  $svc -StartupType Disabled -EA SilentlyContinue
            Write-OK "Service killed: $svc"
        } catch { Write-Warn "Could not modify: $svc" }
    }
    Write-Log "Telemetry disabled"
    Write-Warn "Restart recommended."
    Pause-Screen
}

function Enable-FirewallHardened {
    if (-not (Test-AdminPrivilege)) { return }
    if (-not (Confirm-Action "Set all firewall profiles ON and block inbound by default?")) { return }
    Write-Host "`n  [>>] Hardening firewall..." -ForegroundColor DarkGreen
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True
    Write-OK "All profiles ON -- Inbound BLOCK / Outbound ALLOW"
    $blockPorts = @(
        @{Port=23;   Name="Telnet"},
        @{Port=135;  Name="RPC"},
        @{Port=139;  Name="NetBIOS"},
        @{Port=445;  Name="SMB"},
        @{Port=3389; Name="RDP"}
    )
    foreach ($bp in $blockPorts) {
        $ruleName = "WinOpSec-Block-$($bp.Name)"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -EA SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $bp.Port -Action Block | Out-Null
            Write-OK "Blocked inbound :$($bp.Port) ($($bp.Name))"
        } else {
            Write-Dim "Rule exists: $ruleName"
        }
    }
    Write-Log "Firewall hardened"
    Pause-Screen
}

function Disable-RemoteDesktop {
    if (-not (Test-AdminPrivilege)) { return }
    if (-not (Confirm-Action "DISABLE Remote Desktop (RDP)?")) { return }
    Write-Host "`n  [>>] Disabling RDP..." -ForegroundColor DarkGreen
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -EA SilentlyContinue
    Stop-Service TermService -Force -EA SilentlyContinue
    Set-Service  TermService -StartupType Disabled -EA SilentlyContinue
    Write-OK "RDP disabled + firewall rules removed."
    Write-Log "RDP disabled"
    Pause-Screen
}

function Disable-GuestAccount {
    if (-not (Test-AdminPrivilege)) { return }
    Write-Host "`n  [>>] Disabling Guest account..." -ForegroundColor DarkGreen
    try {
        Disable-LocalUser -Name "Guest" -EA Stop
        Write-OK "Guest account disabled."
        Write-Log "Guest account disabled"
    } catch { Write-Warn "Guest already disabled or not found." }
    Pause-Screen
}

function Show-BitLockerStatus {
    Write-Host "`n  [>>] BitLocker status check..." -ForegroundColor DarkGreen
    Write-Host ""
    try {
        $vols = Get-BitLockerVolume -EA Stop
        foreach ($v in $vols) {
            $color = if ($v.ProtectionStatus -eq "On") { "Green" } else { "Red" }
            Write-Host ("  [DRIVE {0}]  Protection: {1}  Volume: {2}" -f $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus) -ForegroundColor $color
        }
        Write-Dim "To enable: Control Panel > BitLocker Drive Encryption"
    } catch { Write-Err "BitLocker not available on this Windows edition." }
    Write-Log "BitLocker check done"
    Pause-Screen
}

function Get-UserAccountAudit {
    Write-Host "`n  [>>] Local user accounts..." -ForegroundColor DarkGreen
    Write-Host ""
    $users = Get-LocalUser
    Write-Host ("  {0,-25} {1,-10} {2,-10} {3}" -f "USERNAME","ENABLED","PWD REQ","LAST LOGON") -ForegroundColor Green
    Write-Host ("  " + "-" * 65) -ForegroundColor DarkGreen
    foreach ($u in $users) {
        $color = if ($u.Enabled) { "White" } else { "DarkGray" }
        $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd") } else { "Never" }
        Write-Host ("  {0,-25} {1,-10} {2,-10} {3}" -f $u.Name, $u.Enabled, $u.PasswordRequired, $lastLogon) -ForegroundColor $color
    }
    Write-Log "User account audit done"
    Pause-Screen
}

# ============================================================
#  PRIVACY CLEANUP
# ============================================================
function Clear-TempFiles {
    if (-not (Confirm-Action "Clear TEMP folders and Windows prefetch?")) { return }
    Write-Host "`n  [>>] Wiping temp files..." -ForegroundColor DarkGreen
    $paths = @($env:TEMP, "C:\Windows\Temp", "C:\Windows\Prefetch")
    $total = 0
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $size = (Get-ChildItem $p -Recurse -Force -EA SilentlyContinue | Measure-Object Length -Sum -EA SilentlyContinue).Sum
            Get-ChildItem $p -Recurse -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue
            $mb = [Math]::Round($size / 1MB, 2)
            $total += $mb
            Write-OK "$p  (~$mb MB)"
        }
    }
    Write-Host ""
    Write-Host "  [>>] TOTAL FREED: $total MB" -ForegroundColor Green
    Write-Log "Temp cleared: $total MB"
    Pause-Screen
}

function Clear-EventLogs {
    if (-not (Test-AdminPrivilege)) { return }
    if (-not (Confirm-Action "CLEAR ALL Windows Event Logs? This is irreversible.")) { return }
    Write-Host "`n  [>>] Wiping event logs..." -ForegroundColor DarkGreen
    $logs = wevtutil el
    foreach ($log in $logs) {
        try { wevtutil cl $log 2>&1 | Out-Null; Write-Dim "Cleared: $log" } catch {}
    }
    Write-OK "All event logs cleared."
    Write-Log "Event logs cleared"
    Pause-Screen
}

function Invoke-DNSFlush {
    Write-Host "`n  [>>] Flushing DNS cache..." -ForegroundColor DarkGreen
    ipconfig /flushdns | Out-Null
    Write-OK "DNS cache flushed."
    Write-Log "DNS flushed"
    Pause-Screen
}

function Clear-RecentFiles {
    if (-not (Confirm-Action "Clear your Recent Files list?")) { return }
    Write-Host "`n  [>>] Clearing recent files..." -ForegroundColor DarkGreen
    $path = [Environment]::GetFolderPath("Recent")
    Get-ChildItem $path -Force -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    Write-OK "Recent files list cleared."
    Write-Log "Recent files cleared"
    Pause-Screen
}

function Show-StartupApps {
    Write-Host "`n  [>>] Startup applications..." -ForegroundColor DarkGreen
    Write-Host ""
    $apps = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
    Write-Host ("  {0,-30} {1,-20} {2}" -f "NAME","USER","COMMAND") -ForegroundColor Green
    Write-Host ("  " + "-" * 80) -ForegroundColor DarkGreen
    foreach ($a in $apps) {
        $shortName = if ($a.Name -and $a.Name.Length -gt 28)       { $a.Name.Substring(0,27) + "..." }    else { $a.Name }
        $shortCmd  = if ($a.Command -and $a.Command.Length -gt 40) { $a.Command.Substring(0,39) + "..." } else { $a.Command }
        Write-Host ("  {0,-30} {1,-20} {2}" -f $shortName, $a.User, $shortCmd) -ForegroundColor White
    }
    Write-Log "Startup apps listed"
    Pause-Screen
}

# ============================================================
#  NETWORK TOOLS
# ============================================================
function Run-SpeedTest {
    Write-Host "`n  [>>] Speed test via Cloudflare (10 MB)..." -ForegroundColor DarkGreen
    try {
        $url   = "https://speed.cloudflare.com/__down?bytes=10000000"
        $start = Get-Date
        $null  = Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 30
        $elapsed = ((Get-Date) - $start).TotalSeconds
        $mbps  = [Math]::Round((10 / $elapsed) * 8, 2)
        Write-Host ""
        Write-Host "  [>>] RESULT: $mbps Mbps  ($([Math]::Round($elapsed,2))s for 10 MB)" -ForegroundColor Green
        Write-Log "Speed test: $mbps Mbps"
    } catch { Write-Err "Speed test failed -- check connection." }
    Pause-Screen
}

function Run-Traceroute {
    Write-Host ""
    $target = Read-Host "  [?] Enter hostname or IP"
    if (-not $target) { return }
    Write-Host "`n  [>>] Tracing route to $target ..." -ForegroundColor DarkGreen
    Write-Host ""
    tracert -h 20 $target
    Write-Log "Traceroute: $target"
    Pause-Screen
}

function Show-WifiPasswords {
    if (-not (Test-AdminPrivilege)) { return }
    Write-Host "`n  [>>] Saved Wi-Fi credentials..." -ForegroundColor DarkGreen
    Write-Host ""
    $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() }
    foreach ($p in $profiles) {
        $details = netsh wlan show profile name="$p" key=clear 2>&1
        $pw = ($details | Select-String "Key Content") -replace ".*: ",""
        $color = if ($pw) { "Green" } else { "DarkGray" }
        Write-Host ("  {0,-35} >> {1}" -f $p, $(if($pw){$pw}else{"(hidden/none)"})) -ForegroundColor $color
    }
    Write-Log "Wi-Fi passwords viewed"
    Pause-Screen
}

function Show-ARPTable {
    Write-Host "`n  [>>] ARP table -- local network devices..." -ForegroundColor DarkGreen
    Write-Host ""
    arp -a
    Write-Log "ARP table displayed"
    Pause-Screen
}

# ============================================================
#  SYSTEM INFO + HARDWARE SERIALS
# ============================================================
function Show-SystemInfo {
    Write-Host "`n  [>>] System Overview..." -ForegroundColor DarkGreen
    Write-Host ""
    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem
    $cpu  = Get-CimInstance Win32_Processor
    $bios = Get-CimInstance Win32_BIOS
    $mb   = Get-CimInstance Win32_BaseBoard
    $secureBoot = try { if (Confirm-SecureBootUEFI) { "ENABLED" } else { "DISABLED" } } catch { "N/A" }

    Write-Host "  [-- SYSTEM --]" -ForegroundColor Green
    Write-Host ("  {0,-18}: {1}" -f "Computer",    $cs.Name)                         -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "User",        "$env:USERDOMAIN\$env:USERNAME")  -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "OS",          "$($os.Caption) $($os.OSArchitecture)") -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Build",       $os.BuildNumber)                  -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Uptime (hr)", [Math]::Round(($os.LocalDateTime - $os.LastBootUpTime).TotalHours, 1)) -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Secure Boot", $secureBoot)                      -ForegroundColor $(if($secureBoot -eq "ENABLED"){"Green"}else{"Yellow"})
    Write-Host ""

    Write-Host "  [-- CPU --]" -ForegroundColor Green
    Write-Host ("  {0,-18}: {1}" -f "Model",       $cpu.Name)                        -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Cores/Threads","$($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)") -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Speed",       "$($cpu.MaxClockSpeed) MHz")      -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Serial",      $(if($cpu.ProcessorId){"$($cpu.ProcessorId)"}else{"N/A"})) -ForegroundColor Red
    Write-Host ""

    Write-Host "  [-- RAM --]" -ForegroundColor Green
    $totalRam = [Math]::Round($cs.TotalPhysicalMemory/1GB,1)
    Write-Host ("  {0,-18}: {1} GB" -f "Total RAM", $totalRam) -ForegroundColor White
    try {
        $dimms = Get-CimInstance Win32_PhysicalMemory
        $slot  = 1
        foreach ($d in $dimms) {
            $gb = [Math]::Round($d.Capacity/1GB,1)
            Write-Host ("  {0,-18}: {1} GB  {2}  Serial: {3}" -f "Slot $slot", $gb, $d.Manufacturer, $(if($d.SerialNumber){"$($d.SerialNumber)"}else{"N/A"})) -ForegroundColor Red
            $slot++
        }
    } catch { Write-Dim "Could not read DIMM info." }
    Write-Host ""

    Write-Host "  [-- MOTHERBOARD --]" -ForegroundColor Green
    Write-Host ("  {0,-18}: {1}" -f "Manufacturer", $mb.Manufacturer)               -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Product",      $mb.Product)                    -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Serial",       $(if($mb.SerialNumber){"$($mb.SerialNumber)"}else{"N/A"})) -ForegroundColor Red
    Write-Host ""

    Write-Host "  [-- BIOS --]" -ForegroundColor Green
    Write-Host ("  {0,-18}: {1}" -f "Manufacturer", $bios.Manufacturer)             -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Version",      $bios.SMBIOSBIOSVersion)        -ForegroundColor White
    Write-Host ("  {0,-18}: {1}" -f "Serial",       $(if($bios.SerialNumber){"$($bios.SerialNumber)"}else{"N/A"})) -ForegroundColor Red
    Write-Host ""

    Write-Host "  [-- STORAGE --]" -ForegroundColor Green
    try {
        $disks = Get-CimInstance Win32_DiskDrive
        foreach ($disk in $disks) {
            $sizeGB = [Math]::Round($disk.Size/1GB,1)
            $diskSerial = if($disk.SerialNumber){"$($disk.SerialNumber.Trim())"}else{"N/A"}
            Write-Host ("  {0,-18}: {1}  {2} GB  Serial: " -f $disk.Model, $disk.InterfaceType, $sizeGB) -ForegroundColor White -NoNewline
            Write-Host $diskSerial -ForegroundColor Red
        }
    } catch { Write-Dim "Could not read disk info." }
    Write-Host ""

    Write-Host "  [-- GPU --]" -ForegroundColor Green
    try {
        $gpus = Get-CimInstance Win32_VideoController
        foreach ($g in $gpus) {
            $vramMB = [Math]::Round($g.AdapterRAM/1MB,0)
            Write-Host ("  {0,-18}: {1}  VRAM: {2} MB" -f "Adapter", $g.Name, $vramMB) -ForegroundColor White
            Write-Host ("  {0,-18}: {1}" -f "Driver Ver", $g.DriverVersion)             -ForegroundColor DarkGreen
        }
    } catch { Write-Dim "Could not read GPU info." }
    Write-Host ""

    Write-Host "  [-- NETWORK ADAPTERS --]" -ForegroundColor Green
    try {
        $nics = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
        foreach ($n in $nics) {
            Write-Host ("  {0,-18}: {1}" -f "Adapter", $n.Name)           -ForegroundColor White
            Write-Host ("  {0,-18}: {1}" -f "MAC", $n.MACAddress)         -ForegroundColor Red
        }
    } catch { Write-Dim "Could not read NIC info." }

    Write-Log "System info + serials displayed"
    Pause-Screen
}

function Show-DiskUsage {
    Write-Host "`n  [>>] Disk usage..." -ForegroundColor DarkGreen
    Write-Host ""
    $drives = Get-PSDrive -PSProvider FileSystem
    foreach ($d in $drives) {
        if ($null -ne $d.Used -and $null -ne $d.Free) {
            $total = $d.Used + $d.Free
            $pct   = [Math]::Round(($d.Used / $total) * 100, 1)
            $bars  = [int]($pct / 5)
            $bar   = ("#" * $bars).PadRight(20, "-")
            $color = if ($pct -gt 85) { "Red" } elseif ($pct -gt 65) { "Yellow" } else { "Green" }
            Write-Host ("  [{0}]  [{1}]  {2,5}%   Used: {3,7} GB   Free: {4,7} GB" -f `
                $d.Name, $bar, $pct,
                [Math]::Round($d.Used/1GB,1),
                [Math]::Round($d.Free/1GB,1)) -ForegroundColor $color
        }
    }
    Write-Log "Disk usage checked"
    Pause-Screen
}

function Show-TopProcesses {
    Write-Host "`n  [>>] Top 15 processes by CPU..." -ForegroundColor DarkGreen
    Write-Host ""
    $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 15
    Write-Host ("  {0,-30} {1,-10} {2,-12} {3}" -f "PROCESS","PID","RAM (MB)","CPU (s)") -ForegroundColor Green
    Write-Host ("  " + "-" * 65) -ForegroundColor DarkGreen
    foreach ($p in $procs) {
        $shortName = if ($p.Name.Length -gt 28) { $p.Name.Substring(0,27) + ".." } else { $p.Name }
        Write-Host ("  {0,-30} {1,-10} {2,-12} {3}" -f `
            $shortName, $p.Id,
            [Math]::Round($p.WorkingSet64/1MB,1),
            [Math]::Round($p.CPU,1)) -ForegroundColor White
    }
    Write-Log "Top processes displayed"
    Pause-Screen
}

# ============================================================
#  SUB-MENUS
# ============================================================
function Show-OpSecMenu {
    $items = @(
        @{Name="External IP Info";        Desc="Public IP + ISP lookup"},
        @{Name="DNS Leak Check";          Desc="View configured DNS servers"},
        @{Name="Open Ports";              Desc="Listening ports on this machine"},
        @{Name="Active Connections";      Desc="Established internet connections"},
        @{Name="Scheduled Tasks Audit";   Desc="Non-Microsoft scheduled tasks"},
        @{Name="Autorun/Startup Entries"; Desc="Registry autorun keys"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "OPSEC / PRIVACY CHECKS" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Show-ExternalIP }
            "2" { Show-DNSLeakTest }
            "3" { Show-OpenPorts }
            "4" { Show-ActiveConnections }
            "5" { Show-ScheduledTasksAudit }
            "6" { Show-AutoRunEntries }
            "0" { return }
        }
    }
}

function Show-HardeningMenu {
    $items = @(
        @{Name="Disable Telemetry";     Desc="Kill MS data collection [ADMIN]"},
        @{Name="Harden Firewall";       Desc="Block risky ports + enforce rules [ADMIN]"},
        @{Name="Disable RDP";           Desc="Turn off Remote Desktop [ADMIN]"},
        @{Name="Disable Guest Account"; Desc="Lock down guest user [ADMIN]"},
        @{Name="BitLocker Status";      Desc="Check drive encryption"},
        @{Name="Audit User Accounts";   Desc="List all local users"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "SYSTEM HARDENING" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Disable-Telemetry }
            "2" { Enable-FirewallHardened }
            "3" { Disable-RemoteDesktop }
            "4" { Disable-GuestAccount }
            "5" { Show-BitLockerStatus }
            "6" { Get-UserAccountAudit }
            "0" { return }
        }
    }
}

function Show-PrivacyMenu {
    $items = @(
        @{Name="Clear Temp Files";   Desc="Free space and wipe traces"},
        @{Name="Clear Event Logs";   Desc="Wipe all Windows event logs [ADMIN]"},
        @{Name="Flush DNS Cache";    Desc="Clear local DNS cache"},
        @{Name="Clear Recent Files"; Desc="Wipe Recent Files list"},
        @{Name="Startup App Audit";  Desc="See what launches at boot"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "PRIVACY CLEANUP" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Clear-TempFiles }
            "2" { Clear-EventLogs }
            "3" { Invoke-DNSFlush }
            "4" { Clear-RecentFiles }
            "5" { Show-StartupApps }
            "0" { return }
        }
    }
}

function Show-NetworkMenu {
    $items = @(
        @{Name="Speed Test";      Desc="Download speed via Cloudflare"},
        @{Name="Traceroute";      Desc="Trace path to a host"},
        @{Name="Wi-Fi Passwords"; Desc="View saved credentials [ADMIN]"},
        @{Name="ARP Table";       Desc="Devices on local network"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "NETWORK TOOLS" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Run-SpeedTest }
            "2" { Run-Traceroute }
            "3" { Show-WifiPasswords }
            "4" { Show-ARPTable }
            "0" { return }
        }
    }
}

function Show-SysInfoMenu {
    $items = @(
        @{Name="System Overview + Serials"; Desc="Full hardware info, serials, GPU, NICs"},
        @{Name="Disk Usage";                Desc="Visual bar per drive"},
        @{Name="Top Processes";             Desc="CPU and RAM hogs"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "SYSTEM INFORMATION" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Show-SystemInfo }
            "2" { Show-DiskUsage }
            "3" { Show-TopProcesses }
            "0" { return }
        }
    }
}



# ============================================================

#  THREAT INTEL / RECON

# ============================================================

function Invoke-IPRepCheck {

    Write-Host ""

    $ip = Read-Host "  [?] Enter IP to check (blank = your external IP)"

    if (-not $ip) {

        try { $ip = (Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 8).ip } catch { Write-Err "Could not get external IP."; Pause-Screen; return }

    }

    Write-Host "`n  [>>] Checking reputation for $ip ..." -ForegroundColor DarkRed

    try {

        $r = Invoke-RestMethod "https://ipinfo.io/$ip/json" -TimeoutSec 8

        Write-Host ""

        Write-Host "  [IP]      " -NoNewline -ForegroundColor DarkRed; Write-Host $r.ip       -ForegroundColor White

        Write-Host "  [HOST]    " -NoNewline -ForegroundColor DarkRed; Write-Host $r.hostname  -ForegroundColor White

        Write-Host "  [CITY]    " -NoNewline -ForegroundColor DarkRed; Write-Host $r.city      -ForegroundColor White

        Write-Host "  [REGION]  " -NoNewline -ForegroundColor DarkRed; Write-Host $r.region    -ForegroundColor White

        Write-Host "  [COUNTRY] " -NoNewline -ForegroundColor DarkRed; Write-Host $r.country   -ForegroundColor White

        Write-Host "  [ORG/ISP] " -NoNewline -ForegroundColor DarkRed; Write-Host $r.org       -ForegroundColor Yellow

        Write-Host "  [POSTAL]  " -NoNewline -ForegroundColor DarkRed; Write-Host $r.postal    -ForegroundColor White

        Write-Host "  [TZ]      " -NoNewline -ForegroundColor DarkRed; Write-Host $r.timezone  -ForegroundColor White

        Write-Host ""

        Write-Warn "For deeper abuse checks visit: https://www.abuseipdb.com/check/$ip"

        Write-Log "IP rep check: $ip"

    } catch { Write-Err "Lookup failed for $ip" }

    Pause-Screen

}



function Invoke-PortScanTarget {

    Write-Host ""

    $target = Read-Host "  [?] Enter hostname or IP to scan"

    if (-not $target) { return }

    $portsInput = Read-Host "  [?] Ports to scan (e.g. 22,80,443,3389 or blank for common)"

    if (-not $portsInput) {

        $ports = @(21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5985,8080,8443)

    } else {

        $ports = $portsInput -split "," | ForEach-Object { [int]$_.Trim() }

    }

    Write-Host "`n  [>>] Scanning $target ..." -ForegroundColor DarkRed

    Write-Host ("  {0,-8} {1,-10} {2}" -f "PORT","STATUS","BANNER") -ForegroundColor Red

    Write-Host ("  " + "-" * 50) -ForegroundColor DarkRed

    foreach ($port in $ports) {

        $tcp = New-Object System.Net.Sockets.TcpClient

        try {

            $conn = $tcp.BeginConnect($target, $port, $null, $null)

            $wait = $conn.AsyncWaitHandle.WaitOne(500, $false)

            if ($wait -and $tcp.Connected) {

                Write-Host ("  {0,-8} {1,-10}" -f $port, "OPEN") -ForegroundColor Red -NoNewline

                # Try grab banner

                try {

                    $stream = $tcp.GetStream(); $stream.ReadTimeout = 300

                    $buf = New-Object byte[] 256

                    $read = $stream.Read($buf, 0, 256)

                    $banner = [Text.Encoding]::ASCII.GetString($buf, 0, $read).Trim() -replace "`r|`n"," "

                    if ($banner.Length -gt 40) { $banner = $banner.Substring(0,40) + "..." }

                    Write-Host " $banner" -ForegroundColor Yellow

                } catch { Write-Host "" }

            } else {

                Write-Host ("  {0,-8} {1,-10}" -f $port, "closed") -ForegroundColor DarkGray

            }

        } catch { Write-Host ("  {0,-8} {1,-10}" -f $port, "filtered") -ForegroundColor DarkGray }

        finally { $tcp.Close() }

    }

    Write-Log "Port scan: $target"

    Pause-Screen

}



function Get-WhoIsLookup {

    Write-Host ""

    $target = Read-Host "  [?] Enter domain or IP for WHOIS"

    if (-not $target) { return }

    Write-Host "`n  [>>] WHOIS lookup for $target ..." -ForegroundColor DarkRed

    try {

        $r = Invoke-RestMethod "https://api.whoisjson.com/v1/$target" -TimeoutSec 10 -EA Stop

        Write-Host ""

        if ($r.domain)     { Write-Host ("  {0,-18}: {1}" -f "Domain",     $r.domain)     -ForegroundColor White }

        if ($r.registrar)  { Write-Host ("  {0,-18}: {1}" -f "Registrar",  $r.registrar)  -ForegroundColor White }

        if ($r.created)    { Write-Host ("  {0,-18}: {1}" -f "Created",    $r.created)    -ForegroundColor White }

        if ($r.expires)    { Write-Host ("  {0,-18}: {1}" -f "Expires",    $r.expires)    -ForegroundColor Yellow }

        if ($r.nameserver) { Write-Host ("  {0,-18}: {1}" -f "Nameserver", ($r.nameserver -join ", ")) -ForegroundColor White }

    } catch {

        Write-Warn "WHOIS API unavailable. Opening in browser..."

        Start-Process "https://who.is/whois/$target"

    }

    Write-Log "WHOIS: $target"

    Pause-Screen

}



function Get-DNSRecords {

    Write-Host ""

    $domain = Read-Host "  [?] Enter domain"

    if (-not $domain) { return }

    Write-Host "`n  [>>] DNS records for $domain ..." -ForegroundColor DarkRed

    Write-Host ""

    $types = @("A","AAAA","MX","NS","TXT","CNAME")

    foreach ($t in $types) {

        try {

            $res = Resolve-DnsName -Name $domain -Type $t -EA SilentlyContinue

            if ($res) {

                Write-Host "  [$t]" -ForegroundColor Red

                foreach ($r in $res) {

                    $val = if ($r.IPAddress) { $r.IPAddress } elseif ($r.NameHost) { $r.NameHost } elseif ($r.Strings) { $r.Strings -join " " } elseif ($r.Exchange) { "$($r.Exchange) (pref $($r.Preference))" } else { $r.Name }

                    Write-Host "    >> $val" -ForegroundColor White

                }

                Write-Host ""

            }

        } catch {}

    }

    Write-Log "DNS records: $domain"

    Pause-Screen

}



function Show-PingMonitor {

    Write-Host ""

    $target = Read-Host "  [?] Host to monitor (blank = 8.8.8.8)"

    if (-not $target) { $target = "8.8.8.8" }

    $count = Read-Host "  [?] How many pings? (blank = 10)"

    if (-not $count) { $count = 10 } else { $count = [int]$count }

    Write-Host "`n  [>>] Pinging $target x$count ..." -ForegroundColor DarkRed

    Write-Host ""

    $results = @()

    for ($i = 1; $i -le $count; $i++) {

        $p = Test-Connection -ComputerName $target -Count 1 -EA SilentlyContinue

        if ($p) {

            $ms = $p.ResponseTime

            $results += $ms

            $bar = "#" * [Math]::Min([int]($ms / 5), 40)

            $col = if ($ms -gt 150) { "Red" } elseif ($ms -gt 60) { "Yellow" } else { "Green" }

            Write-Host ("  [{0,3}]  {1,5} ms  {2}" -f $i, $ms, $bar) -ForegroundColor $col

        } else {

            $results += 9999

            Write-Host ("  [{0,3}]  TIMEOUT" -f $i) -ForegroundColor Red

        }

        Start-Sleep -Milliseconds 500

    }

    $valid = $results | Where-Object { $_ -ne 9999 }

    if ($valid) {

        $avg  = [Math]::Round(($valid | Measure-Object -Average).Average, 1)

        $minV = ($valid | Measure-Object -Minimum).Minimum

        $maxV = ($valid | Measure-Object -Maximum).Maximum

        $lost = $results.Count - $valid.Count

        Write-Host ""

        Write-Host ("  [AVG] {0} ms   [MIN] {1} ms   [MAX] {2} ms   [LOSS] {3}/{4}" -f $avg, $minV, $maxV, $lost, $count) -ForegroundColor Green

    }

    Write-Log "Ping monitor: $target"

    Pause-Screen

}



# ============================================================

#  PROCESS & SECURITY CHECKS

# ============================================================

function Get-SuspiciousProcesses {

    Write-Host "`n  [>>] Scanning for suspicious process indicators..." -ForegroundColor DarkRed

    Write-Host ""

    $suspicious = @()

    $procs = Get-Process -EA SilentlyContinue

    foreach ($p in $procs) {

        $flags = @()

        # No window + no description

        if ($p.MainWindowHandle -eq 0 -and -not $p.Description -and $p.Name -notmatch "^(svchost|conhost|csrss|lsass|winlogon|services|smss|wininit|RuntimeBroker|sihost|taskhostw|fontdrvhost)$") {

            $flags += "NoWindow+NoDesc"

        }

        # Running from temp or appdata

        try {

            $path = $p.MainModule.FileName

            if ($path -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\") { $flags += "SuspiciousPath" }

            if ($path -match "\\AppData\\Roaming\\" -and $p.Name -notmatch "discord|slack|teams|code") { $flags += "RoamingAppData" }

        } catch {}

        if ($flags.Count -gt 0) {

            $suspicious += [PSCustomObject]@{ Name=$p.Name; PID=$p.Id; Flags=$flags -join "|" }

        }

    }

    if ($suspicious.Count -eq 0) {

        Write-OK "No obviously suspicious processes detected."

    } else {

        Write-Warn "$($suspicious.Count) process(es) flagged for review:"

        Write-Host ""

        Write-Host ("  {0,-25} {1,-8} {2}" -f "PROCESS","PID","FLAGS") -ForegroundColor Red

        Write-Host ("  " + "-" * 60) -ForegroundColor DarkRed

        foreach ($s in $suspicious) {

            Write-Host ("  {0,-25} {1,-8} {2}" -f $s.Name, $s.PID, $s.Flags) -ForegroundColor Yellow

        }

    }

    Write-Log "Suspicious process scan done"

    Pause-Screen

}



function Get-InstalledSoftwareAudit {

    Write-Host "`n  [>>] Installed software audit..." -ForegroundColor DarkRed

    Write-Host ""

    $paths = @(

        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",

        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",

        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    )

    $apps = $paths | ForEach-Object {

        Get-ItemProperty $_ -EA SilentlyContinue |

        Where-Object { $_.DisplayName } |

        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    } | Sort-Object DisplayName -Unique

    Write-Host ("  {0,-45} {1,-15} {2}" -f "NAME","VERSION","PUBLISHER") -ForegroundColor Red

    Write-Host ("  " + "-" * 85) -ForegroundColor DarkRed

    foreach ($a in $apps) {

        $shortName = if ($a.DisplayName.Length -gt 43) { $a.DisplayName.Substring(0,42) + "." } else { $a.DisplayName }

        $shortPub  = if ($a.Publisher -and $a.Publisher.Length -gt 20) { $a.Publisher.Substring(0,19) + "." } else { $a.Publisher }

        Write-Host ("  {0,-45} {1,-15} {2}" -f $shortName, $a.DisplayVersion, $shortPub) -ForegroundColor White

    }

    Write-Host ""

    Write-Dim "Total: $($apps.Count) apps found"

    Write-Log "Software audit done: $($apps.Count) apps"

    Pause-Screen

}



function Get-RecentFileActivity {

    Write-Host "`n  [>>] Recently modified files (last 24h)..." -ForegroundColor DarkRed

    Write-Host ""

    $cutoff = (Get-Date).AddHours(-24)

    $searchPaths = @($env:USERPROFILE + "\Documents", $env:USERPROFILE + "\Desktop", $env:USERPROFILE + "\Downloads")

    $files = @()

    foreach ($sp in $searchPaths) {

        if (Test-Path $sp) {

            $files += Get-ChildItem $sp -Recurse -File -EA SilentlyContinue |

                      Where-Object { $_.LastWriteTime -gt $cutoff } |

                      Select-Object FullName, LastWriteTime, @{N="SizeMB";E={[Math]::Round($_.Length/1MB,2)}}

        }

    }

    if ($files.Count -eq 0) {

        Write-OK "No files modified in the last 24 hours in monitored paths."

    } else {

        Write-Host ("  {0,-55} {1,-22} {2}" -f "FILE","MODIFIED","SIZE MB") -ForegroundColor Red

        Write-Host ("  " + "-" * 85) -ForegroundColor DarkRed

        foreach ($f in ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 40)) {

            $short = if ($f.FullName.Length -gt 53) { "..." + $f.FullName.Substring($f.FullName.Length-50) } else { $f.FullName }

            Write-Host ("  {0,-55} {1,-22} {2}" -f $short, $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"), $f.SizeMB) -ForegroundColor White

        }

        Write-Dim "Showing up to 40 most recent. Total: $($files.Count)"

    }

    Write-Log "Recent file activity: $($files.Count) files"

    Pause-Screen

}



function Export-FullReport {

    $outFile = "$env:USERPROFILE\Desktop\WinOpSec_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

    Write-Host "`n  [>>] Generating full system report..." -ForegroundColor DarkRed

    $lines = @()

    $lines += "=" * 70

    $lines += "  WINOPSEC FULL REPORT  --  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    $lines += "  F SOCIETY UTILITY"

    $lines += "=" * 70

    $lines += ""



    # System

    $cs  = Get-CimInstance Win32_ComputerSystem

    $os  = Get-CimInstance Win32_OperatingSystem

    $cpu = Get-CimInstance Win32_Processor

    $lines += "[SYSTEM]"

    $lines += "  Host     : $($cs.Name)"

    $lines += "  User     : $env:USERDOMAIN\$env:USERNAME"

    $lines += "  OS       : $($os.Caption) $($os.OSArchitecture)"

    $lines += "  Build    : $($os.BuildNumber)"

    $lines += "  CPU      : $($cpu.Name)"

    $lines += "  RAM      : $([Math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB"

    $lines += "  Uptime   : $([Math]::Round(($os.LocalDateTime - $os.LastBootUpTime).TotalHours,1)) hr"

    $lines += ""



    # External IP

    $lines += "[EXTERNAL IP]"

    try {

        $ip = Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 6

        $lines += "  IP: $($ip.ip)  ORG: $($ip.org)  COUNTRY: $($ip.country)"

    } catch { $lines += "  Could not retrieve." }

    $lines += ""



    # DNS

    $lines += "[DNS SERVERS]"

    $adapters = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 }

    foreach ($a in $adapters) { $lines += "  $($a.InterfaceAlias): $($a.ServerAddresses -join ', ')" }

    $lines += ""



    # Open ports

    $lines += "[LISTENING PORTS]"

    Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object -First 30 | ForEach-Object {

        $proc = try { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName } catch { "unknown" }

        $lines += "  :$($_.LocalPort)  $proc  (PID $($_.OwningProcess))"

    }

    $lines += ""



    # Users

    $lines += "[LOCAL USERS]"

    Get-LocalUser | ForEach-Object { $lines += "  $($_.Name)  Enabled:$($_.Enabled)  PwdRequired:$($_.PasswordRequired)" }

    $lines += ""



    # Installed apps count

    $apps = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*") |

            ForEach-Object { Get-ItemProperty $_ -EA SilentlyContinue | Where-Object { $_.DisplayName } }

    $lines += "[INSTALLED SOFTWARE]  ($($apps.Count) apps)"

    $apps | Sort-Object DisplayName | ForEach-Object { $lines += "  $($_.DisplayName)  $($_.DisplayVersion)" }

    $lines += ""



    $lines += "=" * 70

    $lines += "  Report generated by WinOpSec // F Society"

    $lines += "=" * 70



    $lines | Out-File -FilePath $outFile -Encoding UTF8

    Write-OK "Report saved to: $outFile"

    Write-Log "Full report exported: $outFile"

    Pause-Screen

}



# ============================================================

#  THREAT INTEL SUB-MENU

# ============================================================

function Show-ThreatIntelMenu {

    $items = @(

        @{Name="IP Reputation Lookup";  Desc="Geo + ISP info on any IP"},

        @{Name="Port Scanner";          Desc="TCP connect scan against any host"},

        @{Name="WHOIS Lookup";          Desc="Domain/IP registration info"},

        @{Name="DNS Record Lookup";     Desc="A, MX, TXT, NS, CNAME records"},

        @{Name="Ping Monitor";          Desc="Latency + packet loss test"}

    )

    while ($true) {

        Show-Banner

        Show-Menu -Title "THREAT INTEL / RECON" -Items $items

        $choice = Read-Host "  [?] Select"

        switch ($choice) {

            "1" { Invoke-IPRepCheck }

            "2" { Invoke-PortScanTarget }

            "3" { Get-WhoIsLookup }

            "4" { Get-DNSRecords }

            "5" { Show-PingMonitor }

            "0" { return }

        }

    }

}



# ============================================================

#  PROCESS & ACTIVITY SUB-MENU

# ============================================================

function Show-ProcessActivityMenu {

    $items = @(

        @{Name="Suspicious Process Scan";   Desc="Flag unusual/hidden processes"},

        @{Name="Installed Software Audit";  Desc="Full list of installed apps"},

        @{Name="Recent File Activity";      Desc="Files modified in last 24 hours"},

        @{Name="Export Full Report";        Desc="Save complete system report to Desktop"}

    )

    while ($true) {

        Show-Banner

        Show-Menu -Title "PROCESS / ACTIVITY" -Items $items

        $choice = Read-Host "  [?] Select"

        switch ($choice) {

            "1" { Get-SuspiciousProcesses }

            "2" { Get-InstalledSoftwareAudit }

            "3" { Get-RecentFileActivity }

            "4" { Export-FullReport }

            "0" { return }

        }

    }

}



# ============================================================
#  MAIN MENU
# ============================================================
function Show-MainMenu {
    $items = @(
        @{Name="OpSec / Privacy Checks"; Desc="IP, DNS, ports, connections, autoruns"},
        @{Name="System Hardening";       Desc="Firewall, telemetry, RDP, accounts"},
        @{Name="Privacy Cleanup";        Desc="Temp files, logs, DNS cache, recents"},
        @{Name="Network Tools";          Desc="Speed test, traceroute, Wi-Fi, ARP"},
        @{Name="System Information";     Desc="Full hardware overview + serials"},
        @{Name="Threat Intel / Recon";   Desc="IP lookup, port scan, WHOIS, DNS, ping"},
        @{Name="Process / Activity";     Desc="Suspicious procs, software audit, file activity, report"}
    )
    while ($true) {
        Show-Banner
        Show-Menu -Title "MAIN MENU" -Items $items
        $choice = Read-Host "  [?] Select"
        switch ($choice) {
            "1" { Show-OpSecMenu }
            "2" { Show-HardeningMenu }
            "3" { Show-PrivacyMenu }
            "4" { Show-NetworkMenu }
            "5" { Show-SysInfoMenu }
            "6" { Show-ThreatIntelMenu }
            "7" { Show-ProcessActivityMenu }
            "0" {
                Clear-Host
                Write-Host ""
                Write-Host "  [**] GOODBYE, $env:USERNAME. [**]" -ForegroundColor Red
                Write-Host ""
                Write-Log "Session ended"
                exit
            }
        }
    }
}

Show-MainMenu
