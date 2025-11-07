<# 
AD Deprovision Audit (DC-auth only) - PowerShell 7
Requires: Windows (Get-WinEvent & Windows Security log)
Behavior parity with PS5.1 build:
- per-file export, consolidated/summary optional, strict Archive-Security-*.evtx, strict yyyy-MM-dd dates,
  green lines for any message containing "✓", default CSV folder = script directory (no "out" subfolder).
#>

# ==========================
# Environment & Settings
# ==========================
$ErrorActionPreference = 'Stop'

# Ensure Windows Platform
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    Write-Host "[Platform] This script must run on Windows (Domain Controller) to access Security logs." -ForegroundColor Red
    exit 1
}

# Script directory resolution for PS7
$ScriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    # If executed in interactive context (e.g., pasted), fall back to current directory
    $ScriptDir = (Get-Location).Path
} else {
    $ScriptDir = Split-Path -Parent $ScriptPath
}

# ==========================
# Console Helpers
# ==========================
function Write-Info($msg) {
    if ($null -ne $msg -and ($msg -match [regex]::Escape("✓"))) {
        Write-Host "$msg" -ForegroundColor Green
    } else {
        Write-Host "$msg"
    }
}
function Write-Green($msg)  { Write-Host "$msg" -ForegroundColor Green }
function Write-Red($msg)    { Write-Host "$msg" -ForegroundColor Red }
function Write-Yellow($msg) { Write-Host "$msg" -ForegroundColor Yellow }
function Write-ProgressNote($activity, $status, $percent) {
    try {
        if ($percent -ge 0 -and $percent -le 100) {
            Write-Progress -Activity $activity -Status $status -PercentComplete $percent
        } else {
            Write-Progress -Activity $activity -Status $status
        }
    } catch { }
}

# ==========================
# Privilege Check
# ==========================
function Test-AdminOrELR {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        $isAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        # Event Log Readers group SID = S-1-5-32-573
        $elrSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-573')
        $isELR = $false
        foreach ($g in $wi.Groups) {
            if ($g.Translate([Security.Principal.SecurityIdentifier]).Value -eq $elrSid.Value) { $isELR = $true; break }
        }
        return ($isAdmin -or $isELR)
    } catch { return $false }
}

# ==========================
# Input/Path Helpers
# ==========================
function Prompt-AbsolutePath([string]$prompt, [string]$default) {
    Write-Host $prompt -NoNewline
    $in = Read-Host
    if ([string]::IsNullOrWhiteSpace($in)) { $in = $default }
    $isAbsolute = ($in -match '^[a-zA-Z]:\\') -or ($in -match '^\\\\')
    if (-not $isAbsolute) { throw "Path must be an absolute path: '$in'" }
    if (-not $in.EndsWith('\')) { $in = $in + '\' }
    return $in
}

# Robust yyyy-MM-dd parsing without throwing
function TryParse-Date([string]$text, [ref]$outDate) {
    try {
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        $styles  = [System.Globalization.DateTimeStyles]::AssumeLocal
        $formats = @('yyyy-MM-dd')
        [datetime]$tmp = [datetime]::MinValue
        $ok = [datetime]::TryParseExact($text, $formats, $culture, $styles, [ref]$tmp)
        if ($ok) { $outDate.Value = $tmp; return $true } else { return $false }
    } catch { return $false }
}

function Read-DateStrict([string]$label, [datetime]$defaultDate, [bool]$allowEmptyDefault=$false) {
    while ($true) {
        $inputStr = Read-Host $label
        if ($allowEmptyDefault -and [string]::IsNullOrWhiteSpace($inputStr)) { return $defaultDate.Date }
        [datetime]$out = [datetime]::MinValue
        if (-not (TryParse-Date $inputStr ([ref]$out))) { Write-Red "Invalid date format. Use YYYY-MM-DD."; continue }
        $today = (Get-Date).Date
        if ($out.Date -gt $today) { Write-Red "Date cannot be in the future."; continue }
        return $out.Date
    }
}

function Confirm-StartEnd([datetime]$start, [datetime]$end) {
    if ($start -gt $end) { throw "Start date cannot be later than end date." }
}

# ==========================
# Event Helpers
# ==========================
function Get-EventName([int]$id) {
    switch ($id) {
        4768 { 'Kerberos TGT was issued' }
        4771 { 'Kerberos pre-auth failed' }
        4776 { 'NTLM authentication' }
        default { "Event $id" }
    }
}

function Select-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)

    $id       = $ev.Id
    $timeUtc  = $ev.TimeCreated.ToUniversalTime().ToString('o')
    $eventNm  = Get-EventName $id

    $xml = [xml]$ev.ToXml()
    $dataNodes = $xml.Event.EventData.Data
    $getVal = {
        param($name)
        foreach ($n in $dataNodes) { if ($n.Name -eq $name) { return [string]$n.'#text' } }
        return $null
    }

    $acct  = (& $getVal 'TargetUserName'); if (-not $acct) { $acct = (& $getVal 'AccountName') }
    $ip    = (& $getVal 'IpAddress'); if (-not $ip) { $ip = (& $getVal 'ClientAddress') }
    $ws    = (& $getVal 'Workstation'); if (-not $ws) { $ws = (& $getVal 'WorkstationName') }
    $lt    = (& $getVal 'LogonType')

    $status = (& $getVal 'Status'); if (-not $status) { $status = (& $getVal 'FailureCode') }
    if (-not $status) { $status = (& $getVal 'SubStatus') }

    if ($id -eq 4768) { $status = 'SUCCESS' }
    elseif ($id -eq 4771) { if (-not $status) { $status = 'FAILED' } }
    elseif ($id -eq 4776) {
        if ($status -and $status.Trim().ToLower() -eq '0x0') { $status = 'SUCCESS' }
    }

    [pscustomobject]@{
        TimestampUTC    = $timeUtc
        EventID         = $id
        EventName       = $eventNm
        Account         = $acct
        ClientAddress   = $ip
        Workstation     = $ws
        LogonType       = $lt
        StatusOrFailure = $status
    }
}

function Build-XPath([int[]]$ids, [datetime]$start, [datetime]$end, [string[]]$users) {
    $startUtc = $start.ToUniversalTime().ToString('o')
    $endUtc   = $end.AddDays(1).AddMilliseconds(-1).ToUniversalTime().ToString('o')

    $idPart = ($ids | ForEach-Object { "EventID=$_"} ) -join ' or '

    $userConds = @()
    foreach ($u in $users) {
        $esc = $u.Replace("'", "&apos;")
        $userConds += "Data[@Name='TargetUserName']='$esc'"
        $userConds += "Data[@Name='AccountName']='$esc'"
    }
    $userPart = ($userConds | ForEach-Object { $_ }) -join ' or '

    $xpath = "*[System[($idPart) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"
    if ($userPart) { $xpath += " and *[EventData[($userPart)]]" }
    return $xpath
}

function Get-FileTimeWindow([string]$path) {
    try {
        $oldest = Get-WinEvent -Path $path -Oldest -MaxEvents 1
        $newest = Get-WinEvent -Path $path -MaxEvents 1
        if ($oldest -and $newest) {
            return [pscustomobject]@{
                Path  = $path
                Start = $oldest.TimeCreated.Date
                End   = $newest.TimeCreated.Date
                Valid = $true
            }
        }
    } catch { }
    return [pscustomobject]@{ Path=$path; Start=$null; End=$null; Valid=$false }
}

function Fetch-EventsFromSource {
    param(
        [ValidateSet('Current','File')][string]$SourceType,
        [string]$PathIfFile,
        [string]$XPath
    )
    if ($SourceType -eq 'Current') {
        return Get-WinEvent -LogName Security -FilterXPath $XPath -ErrorAction Stop
    } else {
        return Get-WinEvent -Path $PathIfFile -FilterXPath $XPath -ErrorAction Stop
    }
}

# ==========================
# Banner & Privileges
# ==========================
Write-Info "# ======================="
Write-Info "# AD Deprovision Audit (DC-auth only)"
Write-Info "# PowerShell 7"
Write-Info "# =======================`n"

if (-not (Test-AdminOrELR)) {
    Write-Red "[Privilege Check] Insufficient privileges. Run as Administrator or a member of 'Event Log Readers'."
    exit 1
}
Write-Info "[Privilege Check]"
Write-Info "✓ You are running with sufficient privileges (Administrators/Event Log Readers).`n"

# ==========================
# Main Menu - Event Scope
# ==========================
Write-Info "[Main Menu - Event Scope]"
Write-Info "1) Successful authentication (4768 + 4776-success)"
Write-Info "2) Failed authentication (4771 + 4776-failure)"
Write-Info "3) Successful + Failed"
$eventChoice = Read-Host "Selection"
$ids = @()
switch ($eventChoice) {
    '1' { $ids = 4768,4776 }
    '2' { $ids = 4771,4776 }
    '3' { $ids = 4768,4771,4776 }
    default { Write-Red "Invalid selection."; exit 1 }
}

# ==========================
# User List
# ==========================
$defaultUserList = Join-Path $ScriptDir 'userlist.txt'
try {
    $pathPrompt = "Enter absolute path to user list (default: $defaultUserList):`n> "
    Write-Host $pathPrompt -NoNewline
    $userListPath = Read-Host
    if ([string]::IsNullOrWhiteSpace($userListPath)) { $userListPath = $defaultUserList }

    $isAbsolute = ($userListPath -match '^[a-zA-Z]:\\') -or ($userListPath -match '^\\\\')
    if (-not $isAbsolute) { throw "Path must be an absolute path: '$userListPath'" }
    if (-not (Test-Path -LiteralPath $userListPath)) { throw "User list not found: $userListPath" }

    $raw = Get-Content -LiteralPath $userListPath -ErrorAction Stop
    $users = $raw | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique
    if (-not $users -or $users.Count -eq 0) { throw "User list is empty." }

    $display = ($users -join ', ')
    Write-Info "✓ Loaded accounts: $display`n"
} catch { Write-Red $_.Exception.Message; exit 1 }

# ==========================
# Period
# ==========================
Write-Info "[Period]"
Write-Info "1) 1 day   2) 1 week   3) 1 month   4) 1 quarter   5) 1 year   6) Custom range"
$periodSel = Read-Host "Selection"
$today = (Get-Date).Date
switch ($periodSel) {
    '1' { $startDate = $today.AddDays(-1); $endDate = $today }
    '2' { $startDate = $today.AddDays(-7); $endDate = $today }
    '3' { $startDate = $today.AddMonths(-1); $endDate = $today }
    '4' { $startDate = $today.AddMonths(-3); $endDate = $today }
    '5' { $startDate = $today.AddYears(-1); $endDate = $today }
    '6' {
        $startDate = Read-DateStrict -label "Start date (YYYY-MM-DD)" -defaultDate $today -allowEmptyDefault:$false
        $endDate   = Read-DateStrict -label "End date   (YYYY-MM-DD) [ENTER = today]" -defaultDate $today -allowEmptyDefault:$true
    }
    default { Write-Red "Invalid selection."; exit 1 }
}
try { Confirm-StartEnd $startDate $endDate } catch { Write-Red $_.Exception.Message; exit 1 }
Write-Info "✓ Parsed range: $($startDate.ToString('yyyy-MM-dd')) ~ $($endDate.ToString('yyyy-MM-dd')) (inclusive)`n"

# ==========================
# Log Sources
# ==========================
Write-Info "[Log Sources]"
Write-Info "1) Current Security log only"
Write-Info "2) Current Security + Archived EVTX"
$logSel = Read-Host "Selection"

$fileList = @()
$coverageStart = $null
$coverageEnd   = $null

if ($logSel -eq '2') {
    try {
        $defaultArchive = $ScriptDir
        $folder = Prompt-AbsolutePath "Archived EVTX folder (absolute path; default = script directory):`n> " $defaultArchive
        if (-not (Test-Path -LiteralPath $folder)) { throw "Folder not found: $folder" }

        $allCandidates = Get-ChildItem -LiteralPath $folder -Filter 'Archive-Security-*.evtx' -File -ErrorAction Stop
        $pattern = '^Archive-Security-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{3}\.evtx$'
        $archCandidates = $allCandidates | Where-Object { $_.Name -match $pattern }
        Write-Info "✓ Discovered $($archCandidates.Count) Archive-Security-*.evtx files"

        $windows = foreach ($fItem in $archCandidates) {
            $w = Get-FileTimeWindow -path $fItem.FullName
            if ($w.Valid) { $w }
        }
        $overlap = $windows | Where-Object { $_.Start -le $endDate -and $_.End -ge $startDate }

        if ($overlap.Count -gt 0) {
            $coverageStart = ($overlap | Measure-Object -Property Start -Minimum).Minimum
            $coverageEnd   = ($overlap | Measure-Object -Property End   -Maximum).Maximum
            Write-Info "✓ Actual searchable coverage: $($coverageStart.ToString('yyyy-MM-dd')) ~ $($coverageEnd.ToString('yyyy-MM-dd'))"
        } else { Write-Yellow "No archived files overlap the requested range." }

        Write-Info "Process order:"
        Write-Info "1) Oldest → Newest"
        Write-Info "2) Newest → Oldest"
        $order = Read-Host "Selection"
        switch ($order) {
            '1' { $fileList = @($overlap | Sort-Object Start | Select-Object -ExpandProperty Path) }
            '2' { $fileList = @($overlap | Sort-Object End -Descending | Select-Object -ExpandProperty Path) }
            default { Write-Red "Invalid selection."; exit 1 }
        }
        if ($fileList -is [string]) { $fileList = @($fileList) }
    } catch { Write-Red $_.Exception.Message; exit 1 }
} elseif ($logSel -ne '1') {
    Write-Red "Invalid selection."
    exit 1
}
Write-Host ""

# ==========================
# Export Settings (per-file)
# ==========================
try {
    $defaultOut = $ScriptDir  # default equals script directory
    $outFolder = Prompt-AbsolutePath "CSV output folder (absolute path; default = $defaultOut):`n> " $defaultOut
    if (-not (Test-Path -LiteralPath $outFolder)) {
        New-Item -ItemType Directory -Path $outFolder -Force | Out-Null
    }
    Write-Info "✓ Per-file export is enabled. File naming:"
    Write-Info "  - Archived EVTX → ADUserLogon-<yyyyMMdd>-<index>.csv"
    Write-Info "  - Current       → ADUserLogon-Current-<yyyyMMdd-HHmmss>.csv"
    Write-Host ""
} catch { Write-Red $_.Exception.Message; exit 1 }

# ==========================
# Build Query & Process
# ==========================
$users = $users | Select-Object -Unique
$xpath = Build-XPath -ids $ids -start $startDate -end $endDate -users $users

$totalCount = 0
$consolidatedBuffer = @()

# ----- Archived files -----
if ($fileList.Count -gt 0) {
    $totalFiles = $fileList.Count
    for ($i=0; $i -lt $totalFiles; $i++) {
        $idx = $i + 1
        $f = $fileList[$i]
        $fileShort = [System.IO.Path]::GetFileName($f)
        $label = "[Processing $idx/$totalFiles]  $fileShort"
        Write-ProgressNote -activity $label -status "Scanning..." -percent 5

        $found = @()
        try {
            $events = Fetch-EventsFromSource -SourceType 'File' -PathIfFile $f -XPath $xpath
            $cnt = 0
            foreach ($ev in $events) {
                $cnt++
                if ($cnt % 50 -eq 0) {
                    $pct = [math]::Min(95, [int](5 + ($cnt % 1000)/10))
                    Write-ProgressNote -activity $label -status "Scanning... ($cnt events matched)" -percent $pct
                }
                $row = Select-EventFields -ev $ev
                $sourceTag = ("Archive-{0}-{1}" -f ($row.TimestampUTC.Substring(0,10).Replace('-','')), $idx)
                $row | Add-Member -NotePropertyName Source -NotePropertyValue $sourceTag
                $row | Add-Member -NotePropertyName SourceFile -NotePropertyValue $fileShort
                $consolidatedBuffer += $row
                $found += $row
            }
            Write-ProgressNote -activity $label -status "Finalizing..." -percent 100
        } catch { Write-Red "Error reading file: $f - $($_.Exception.Message)"; continue }
        finally { Write-Progress -Activity $label -Completed }

        $count = $found.Count
        if ($count -gt 0) { Write-Green ("[########################################] 100% Done          Total: {0} √" -f $count) }
        else { Write-Info ("[########################################] 100% Done          Total: {0} √" -f $count) }

        $dateTag = (Get-Item -LiteralPath $f).LastWriteTime.ToString('yyyyMMdd')
        $outFile = Join-Path $outFolder ("ADUserLogon-{0}-{1}.csv" -f $dateTag, $idx)
        try {
            $found | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8
            Write-Info "→ Exporting CSV..."
            Write-Info "✓ $outFile  ($count rows)`n"
        } catch { Write-Red "Failed to export CSV for $f - $($_.Exception.Message)" }
        $totalCount += $count
    }
}

# ----- Current Security Log -----
Write-Info "[Processing Current Security Log]"
$labelCur = "[Processing Current Security Log]"
Write-ProgressNote -activity $labelCur -status "Scanning..." -percent 5
$currentFound = @()
try {
    $evs = Fetch-EventsFromSource -SourceType 'Current' -XPath $xpath
    $cnt = 0
    foreach ($ev in $evs) {
        $cnt++
        if ($cnt % 100 -eq 0) {
            $pct = [math]::Min(95, [int](5 + ($cnt % 2000)/20))
            Write-ProgressNote -activity $labelCur -status "Scanning... ($cnt events matched)" -percent $pct
        }
        $row = Select-EventFields -ev $ev
        $row | Add-Member -NotePropertyName Source -NotePropertyValue ("Current-{0}" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
        $row | Add-Member -NotePropertyName SourceFile -NotePropertyValue 'CurrentLog'
        $consolidatedBuffer += $row
        $currentFound += $row
    }
    Write-ProgressNote -activity $labelCur -status "Finalizing..." -percent 100
} catch { Write-Red "Error reading current Security log: $($_.Exception.Message)" }
finally { Write-Progress -Activity $labelCur -Completed }

$curCount = $currentFound.Count
if ($curCount -gt 0) { Write-Green ("[########################################] 100% Done          Total: {0} √" -f $curCount) }
else { Write-Info ("[########################################] 100% Done          Total: {0} √" -f $curCount) }

$curName = "ADUserLogon-Current-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
$curOut  = Join-Path $outFolder $curName
try {
    $currentFound | Export-Csv -LiteralPath $curOut -NoTypeInformation -Encoding UTF8
    Write-Info "→ Exporting CSV..."
    Write-Info "✓ $curOut  ($curCount rows)`n"
} catch { Write-Red "Failed to export CSV for current log - $($_.Exception.Message)" }

# ==========================
# Post-Export Options
# ==========================
$grandTotal = $totalCount + $curCount
Write-Info "Per-file exports completed."
Write-Info ("Grand total (archived + current): {0}" -f $grandTotal)
$ansCons = (Read-Host "Also create consolidated CSV at the end? (Y/N)").Trim().ToUpper()
$ansAcct = (Read-Host "Also create per-account summary CSV? (Y/N)").Trim().ToUpper()

if ($ansCons -eq 'Y') {
    try {
        $consName = "ADUserLogon-Consolidated-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
        $consOut  = Join-Path $outFolder $consName
        $consolidatedBuffer | Export-Csv -LiteralPath $consOut -NoTypeInformation -Encoding UTF8
        Write-Info "[Consolidated Export]"
        Write-Info "✓ $consOut  (Total rows: $($consolidatedBuffer.Count))"
    } catch { Write-Red "Failed to export consolidated CSV - $($_.Exception.Message)" }
}

if ($ansAcct -eq 'Y') {
    Write-Info "[Per-Account Summary]"
    try {
        $src = $consolidatedBuffer
        $rows = @()
        if ($src.Count -gt 0) {
            $groups = $src | Group-Object -Property Account
            foreach ($g in $groups) {
                $acc = $g.Name; $success = 0; $fail = 0; $lastUtc = $null; $lastId = $null; $lastSt = $null
                foreach ($r in $g.Group) {
                    $isSuccess = $false
                    if     ($r.EventID -eq 4768) { $isSuccess = $true }
                    elseif ($r.EventID -eq 4771) { $isSuccess = $false }
                    elseif ($r.EventID -eq 4776) { $st = if ($r.StatusOrFailure) { $r.StatusOrFailure.ToString().Trim().ToLower() } else { '' }; if ($st -eq 'success' -or $st -eq '0x0') { $isSuccess = $true } }
                    if ($isSuccess) { $success++ } else { $fail++ }
                    $ts = [datetime]::Parse($r.TimestampUTC)
                    if (-not $lastUtc -or $ts -gt $lastUtc) { $lastUtc = $ts; $lastId = $r.EventID; $lastSt = $r.StatusOrFailure }
                }
                $rows += [pscustomobject]@{
                    Account         = $acc
                    SuccessCount    = $success
                    FailCount       = $fail
                    LastSeenUTC     = if ($lastUtc) { $lastUtc.ToString('o') } else { $null }
                    LastSeenEventID = $lastId
                    LastSeenStatus  = $lastSt
                }
            }
        }
        $sumName = "ADUserLogon-AccountSummary-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
        $sumOut  = Join-Path $outFolder $sumName
        $rows | Sort-Object -Property Account | Export-Csv -LiteralPath $sumOut -NoTypeInformation -Encoding UTF8
        Write-Info "✓ $sumOut"
    } catch { Write-Red "Failed to build account summary - $($_.Exception.Message)" }
}

# ==========================
# Final Summary
# ==========================
Write-Info ""
Write-Info "Summary per file completed."
Write-Info ("Total records across archived + current: {0}" -f $grandTotal)
