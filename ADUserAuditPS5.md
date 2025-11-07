<#
AD User Account Management Audit (DC-auth only)
PowerShell 5.1 Compatible

Events:
- 4720 = Created
- 4722 = Enabled
- 4725 = Disabled
- 4726 = Deleted

Main menu order:
1) 4720  2) 4722  3) 4725  4) 4726  5) 4720+4726  6) 4722+4725  7) All

CSV columns (fixed order):
- Timestamp, EventID, Action, TargetUserName, SubjectUserName, Source

Behavior:
- Default CSV folder = script directory (no 'out' subfolder)
- Per EVTX immediate export; optional consolidated export at end
- Lines containing "✓" print in green automatically
- Archived files restricted to Archive-Security-YYYY-MM-DD-HH-MM-SS-fff.evtx
- Strict YYYY-MM-DD input with validation; End date ENTER = today
- If no events match in a file / current log → export empty CSV and print green ✓ ... (0 rows)
- When choosing "Newest → Oldest", process CURRENT log FIRST, then archived (newest→oldest)
#>

$ErrorActionPreference = 'Stop'

# ---------------- Console helpers ----------------
function Write-Info($msg) {
    if ($null -ne $msg -and ($msg -match [regex]::Escape("✓"))) { Write-Host "$msg" -ForegroundColor Green }
    else { Write-Host "$msg" }
}
function Write-Green($msg){ Write-Host "$msg" -ForegroundColor Green }
function Write-Red($msg)  { Write-Host "$msg" -ForegroundColor Red }
function Write-Yellow($msg){ Write-Host "$msg" -ForegroundColor Yellow }
function Write-ProgressNote($activity,$status,$percent){
    try {
        if ($percent -ge 0 -and $percent -le 100) { Write-Progress -Activity $activity -Status $status -PercentComplete $percent }
        else { Write-Progress -Activity $activity -Status $status }
    } catch {}
}

# ---------------- Privilege check ----------------
function Test-AdminOrELR {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object Security.Principal.WindowsPrincipal($wi)
        $isAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $elrSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-573')
        $isELR = $false
        foreach ($g in $wi.Groups) {
            if ($g.Translate([Security.Principal.SecurityIdentifier]).Value -eq $elrSid.Value) { $isELR = $true; break }
        }
        return ($isAdmin -or $isELR)
    } catch { return $false }
}

# ---------------- Path & date helpers ----------------
function Prompt-AbsolutePath([string]$prompt, [string]$default) {
    Write-Host $prompt -NoNewline
    $in = Read-Host
    if ([string]::IsNullOrWhiteSpace($in)) { $in = $default }
    $isAbsolute = ($in -match '^[a-zA-Z]:\\') -or ($in -match '^\\\\')
    if (-not $isAbsolute) { throw "Path must be an absolute path: '$in'" }
    if (-not $in.EndsWith('\')) { $in += '\' }
    return $in
}
function TryParse-Date([string]$text,[ref]$outDate){
    try{
        $culture=[System.Globalization.CultureInfo]::InvariantCulture
        $styles=[System.Globalization.DateTimeStyles]::AssumeLocal
        $formats=@('yyyy-MM-dd')
        [datetime]$tmp=[datetime]::MinValue
        $ok=[datetime]::TryParseExact($text,$formats,$culture,$styles,[ref]$tmp)
        if($ok){$outDate.Value=$tmp;return $true}else{return $false}
    }catch{ return $false }
}
function Read-DateStrict([string]$label,[datetime]$defaultDate,[bool]$allowEmptyDefault=$false){
    while($true){
        $s=Read-Host $label
        if($allowEmptyDefault -and [string]::IsNullOrWhiteSpace($s)){ return $defaultDate.Date }
        [datetime]$o=[datetime]::MinValue
        if(-not (TryParse-Date $s ([ref]$o))){ Write-Red "Invalid date format. Use YYYY-MM-DD."; continue }
        $today=(Get-Date).Date
        if($o.Date -gt $today){ Write-Red "Date cannot be in the future."; continue }
        return $o.Date
    }
}
function Confirm-StartEnd([datetime]$start,[datetime]$end){
    if($start -gt $end){ throw "Start date cannot be later than end date." }
}

# ---------------- Event helpers ----------------
function Get-ActionName([int]$id){
    switch($id){
        4720 {'Created'}
        4722 {'Enabled'}
        4725 {'Disabled'}
        4726 {'Deleted'}
        default {"Event $id"}
    }
}
function Select-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)

    $id = $ev.Id
    $tsLocal = $ev.TimeCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $xml = [xml]$ev.ToXml()
    $dataNodes = $xml.Event.EventData.Data

    $getVal = {
        param($name)
        foreach ($n in $dataNodes) { if ($n.Name -eq $name) { return [string]$n.'#text' } }
        return $null
    }

    # Affected account (target)
    $target = (& $getVal 'TargetUserName')
    if (-not $target) { $target = (& $getVal 'AccountName') }

    # Executor (subject)
    $subject = (& $getVal 'SubjectUserName')
    if (-not $subject) { $subject = (& $getVal 'SubjectAccountName') }
    if (-not $subject) { $subject = (& $getVal 'CallerUserName') }
    if (-not $subject) { $subject = (& $getVal 'SubjectUserSid') }

    [pscustomobject]@{
        Timestamp        = $tsLocal
        EventID          = $id
        Action           = (Get-ActionName $id)
        TargetUserName   = $target
        SubjectUserName  = $subject
        Source           = ''  # set by caller
    }
}

# XPath builder for selected IDs, time window, and optional account filter
function Build-XPath([int[]]$ids,[datetime]$start,[datetime]$end,[string[]]$users,[bool]$allUsers){
    $startUtc=$start.ToUniversalTime().ToString('o')
    $endUtc=$end.AddDays(1).AddMilliseconds(-1).ToUniversalTime().ToString('o')
    $idPart=($ids|ForEach-Object{"EventID=$_"} ) -join ' or '
    $base="*[System[($idPart) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"
    if($allUsers){ return $base }
    if($users -and $users.Count -gt 0){
        $conds=@()
        foreach($u in $users){
            $esc=$u.Replace("'","&apos;")
            $conds+="Data[@Name='TargetUserName']='$esc'"
            $conds+="Data[@Name='AccountName']='$esc'"
        }
        $userPart=($conds -join ' or ')
        return "$base and *[EventData[($userPart)]]"
    }
    return $base
}

# Quick min/max window per evtx to skip non-overlapping files
function Get-FileTimeWindow([string]$path){
    try{
        $oldest=Get-WinEvent -Path $path -Oldest -MaxEvents 1
        $newest=Get-WinEvent -Path $path -MaxEvents 1
        if($oldest -and $newest){
            return [pscustomobject]@{ Path=$path; Start=$oldest.TimeCreated.Date; End=$newest.TimeCreated.Date; Valid=$true }
        }
    }catch{}
    return [pscustomobject]@{ Path=$path; Start=$null; End=$null; Valid=$false }
}

# ---------------- Safe fetch wrapper ----------------
function Fetch-EventsSafe {
    param(
        [ValidateSet('Current','File')][string]$SourceType,
        [string]$PathIfFile,
        [string]$XPath
    )
    try{
        if($SourceType -eq 'Current'){
            $evs = Get-WinEvent -LogName Security -FilterXPath $XPath -ErrorAction Stop
        } else {
            $evs = Get-WinEvent -Path $PathIfFile -FilterXPath $XPath -ErrorAction Stop
        }
        return [pscustomobject]@{ Events=@($evs); NoMatch=($evs.Count -eq 0); Error=$null }
    }catch{
        $msg = $_.Exception.Message
        if($msg -match 'No events were found that match the specified selection criteria'){
            return [pscustomobject]@{ Events=@(); NoMatch=$true; Error=$null }
        } else {
            return [pscustomobject]@{ Events=@(); NoMatch=$false; Error=$_.Exception }
        }
    }
}

# ---------------- Banner & privilege ----------------
Write-Info "# ======================="
Write-Info "# AD User Account Management Audit"
Write-Info "# PowerShell 5.1"
Write-Info "# =======================`n"

if(-not (Test-AdminOrELR)){
    Write-Red "[Privilege Check] Insufficient privileges. Run as Administrator or a member of 'Event Log Readers'."
    exit 1
}
Write-Info "[Privilege Check]"
Write-Info "✓ You are running with sufficient privileges (Administrators/Event Log Readers).`n"

# ---------------- Main Menu (ordered 1..7) ----------------
Write-Info "[Main Menu - Event Scope]"
Write-Info "1) Account created   (4720)"
Write-Info "2) Account enabled   (4722)"
Write-Info "3) Account disabled  (4725)"
Write-Info "4) Account deleted   (4726)"
Write-Info "5) Account Created + Deleted      (4720+4726)"
Write-Info "6) Account Enabled + Disabled     (4722+475)"
Write-Info "7) All of the above               (4720+4722+4725+4726)"
$choice=Read-Host "Selection"
[int[]]$ids=@()
switch($choice){
    '1' { $ids=4720 }
    '2' { $ids=4722 }
    '3' { $ids=4725 }
    '4' { $ids=4726 }
    '5' { $ids=4720,4726 }
    '6' { $ids=4722,4725 }
    '7' { $ids=4720,4722,4725,4726 }
    default { Write-Red "Invalid selection."; exit 1 }
}

# ---------------- User scope ----------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$defaultUserList = Join-Path $scriptDir 'userlist.txt'

Write-Info "[User List]"
Write-Info "1) All users (no filtering)"
Write-Info "2) Load from userlist.txt (absolute path)"
$uSel = Read-Host "Selection"
$allUsers = $false
[string[]]$users = @()

if($uSel -eq '1'){
    $allUsers = $true
    Write-Info "✓ User scope: All users`n"
}elseif($uSel -eq '2'){
    try{
        $pathPrompt="Enter absolute path to user list (default: $defaultUserList):`n> "
        Write-Host $pathPrompt -NoNewline
        $userListPath=Read-Host
        if([string]::IsNullOrWhiteSpace($userListPath)){$userListPath=$defaultUserList}
        $isAbs=($userListPath -match '^[a-zA-Z]:\\') -or ($userListPath -match '^\\\\')
        if(-not $isAbs){ throw "Path must be an absolute path: '$userListPath'" }
        if(-not (Test-Path -LiteralPath $userListPath)){ throw "User list not found: $userListPath" }
        $raw=Get-Content -LiteralPath $userListPath -ErrorAction Stop
        $users = $raw | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
        if(-not $users -or $users.Count -eq 0){ throw "User list is empty." }
        Write-Info "✓ Loaded accounts: $(($users -join ', '))`n"
    }catch{ Write-Red $_.Exception.Message; exit 1 }
}else{
    Write-Red "Invalid selection."; exit 1
}

# ---------------- Period ----------------
Write-Info "[Period]"
Write-Info "1) 1 day   2) 1 week   3) 1 month   4) 1 quarter   5) 1 year   6) Custom range"
$periodSel=Read-Host "Selection"
$today=(Get-Date).Date
switch($periodSel){
    '1' { $startDate=$today.AddDays(-1); $endDate=$today }
    '2' { $startDate=$today.AddDays(-7); $endDate=$today }
    '3' { $startDate=$today.AddMonths(-1); $endDate=$today }
    '4' { $startDate=$today.AddMonths(-3); $endDate=$today }
    '5' { $startDate=$today.AddYears(-1); $endDate=$today }
    '6' { $startDate=Read-DateStrict -label "Start date (YYYY-MM-DD)" -defaultDate $today -allowEmptyDefault:$false
          $endDate  =Read-DateStrict -label "End date   (YYYY-MM-DD) [ENTER = today]" -defaultDate $today -allowEmptyDefault:$true }
    default { Write-Red "Invalid selection."; exit 1 }
}
try{ Confirm-StartEnd $startDate $endDate }catch{ Write-Red $_.Exception.Message; exit 1 }
Write-Info "✓ Parsed range: $($startDate.ToString('yyyy-MM-dd')) ~ $($endDate.ToString('yyyy-MM-dd')) (inclusive)`n"

# ---------------- Log sources ----------------
Write-Info "[Log Sources]"
Write-Info "1) Current Security log only"
Write-Info "2) Current Security + Archived EVTX"
$logSel=Read-Host "Selection"

$fileList=@()
$coverageStart=$null
$coverageEnd=$null
$processCurrentFirst=$false

if($logSel -eq '2'){
    try{
        $defaultArchive=$scriptDir
        $folder=Prompt-AbsolutePath "Archived EVTX folder (absolute path; default = script directory):`n> " $defaultArchive
        if(-not (Test-Path -LiteralPath $folder)){ throw "Folder not found: $folder" }
        $allCandidates=Get-ChildItem -LiteralPath $folder -Filter 'Archive-Security-*.evtx' -File -ErrorAction Stop
        $pattern='^Archive-Security-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{3}\.evtx$'
        $archCandidates=$allCandidates | Where-Object { $_.Name -match $pattern }
        Write-Info "✓ Discovered $($archCandidates.Count) Archive-Security-*.evtx files"

        $windows=@()
        foreach($fItem in $archCandidates){
            $w=Get-FileTimeWindow -path $fItem.FullName
            if($w.Valid){ $windows+=$w }
        }
        $overlap=$windows | Where-Object { $_.Start -le $endDate -and $_.End -ge $startDate }
        if($overlap.Count -gt 0){
            $coverageStart=($overlap|Measure-Object -Property Start -Minimum).Minimum
            $coverageEnd  =($overlap|Measure-Object -Property End   -Maximum).Maximum
            Write-Info "✓ Actual searchable coverage: $($coverageStart.ToString('yyyy-MM-dd')) ~ $($coverageEnd.ToString('yyyy-MM-dd'))"
        }else{ Write-Yellow "No archived files overlap the requested range." }

        Write-Info "Process order:"
        Write-Info "1) Oldest → Newest"
        Write-Info "2) Newest → Oldest  (Current log will be processed FIRST)"
        $order=Read-Host "Selection"
        switch($order){
            '1' { $fileList=@($overlap | Sort-Object Start | Select-Object -ExpandProperty Path); $processCurrentFirst=$false }
            '2' { $fileList=@($overlap | Sort-Object End -Descending | Select-Object -ExpandProperty Path); $processCurrentFirst=$true }
            default { Write-Red "Invalid selection."; exit 1 }
        }
        if($fileList -is [string]){ $fileList=@($fileList) }
    }catch{ Write-Red $_.Exception.Message; exit 1 }
}elseif($logSel -eq '1'){
    # current only
    $processCurrentFirst=$true  # irrelevant but keeps logic simple
}else{
    Write-Red "Invalid selection."; exit 1
}
Write-Host ""

# ---------------- Export settings ----------------
try{
    $defaultOut=$scriptDir
    $outFolder=Prompt-AbsolutePath "CSV output folder (absolute path; default = $defaultOut):`n> " $defaultOut
    if(-not (Test-Path -LiteralPath $outFolder)){ New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    Write-Info "✓ Per-file export is enabled. File naming:"
    Write-Info "  - Archived EVTX → ADUserAudit-<yyyyMMdd>-<index>.csv"
    Write-Info "  - Current       → ADUserAudit-Current-<yyyyMMdd-HHmmss>.csv"
    Write-Host ""
}catch{ Write-Red $_.Exception.Message; exit 1 }

# ---------------- Query build ----------------
$users = $users | Select-Object -Unique
$xpath = Build-XPath -ids $ids -start $startDate -end $endDate -users $users -allUsers:$allUsers

# ---------------- Helpers to process ----------------
function Process-ArchivedFiles {
    param([string[]]$Files,[string]$XPath,[string]$OutFolder,[ref]$Total,[ref]$Consolidated)

    if(-not $Files -or $Files.Count -eq 0){ return }

    $totalFiles=$Files.Count
    for($i=0;$i -lt $totalFiles;$i++){
        $idx=$i+1
        $f=$Files[$i]
        $fileShort=[System.IO.Path]::GetFileName($f)
        $label="[Processing $idx/$totalFiles]  $fileShort"
        Write-ProgressNote -activity $label -status "Scanning..." -percent 5

        $found=@()
        $fetch = Fetch-EventsSafe -SourceType 'File' -PathIfFile $f -XPath $XPath
        if($fetch.Error){
            Write-Red ("Error reading file: {0} - {1}" -f $f, $fetch.Error.Message)
            Write-Progress -Activity $label -Completed
            continue
        }

        $cnt=0
        foreach($ev in $fetch.Events){
            $cnt++
            if($cnt % 50 -eq 0){ $pct=[math]::Min(95,[int](5+($cnt%1000)/10)); Write-ProgressNote -activity $label -status "Scanning... ($cnt events matched)" -percent $pct }
            $row=Select-EventFields -ev $ev
            $row.Source = $fileShort
            $found += $row
            $Consolidated.Value += $row
        }
        Write-ProgressNote -activity $label -status "Finalizing..." -percent 100
        Write-Progress -Activity $label -Completed

        $count=$found.Count
        if($count -gt 0){ Write-Green ("[########################################] 100% Done          Total: {0} √" -f $count) }
        else{ Write-Info  ("[########################################] 100% Done          Total: {0} √" -f $count) }

        $dateTag=(Get-Item -LiteralPath $f).LastWriteTime.ToString('yyyyMMdd')
        $outFile=Join-Path $OutFolder ("ADUserAudit-{0}-{1}.csv" -f $dateTag,$idx)
        try{
            $found | Select-Object Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source |
                Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8
            Write-Green "✓ $outFile  ($count rows)`n"
        }catch{ Write-Red "Failed to export CSV for $f - $($_.Exception.Message)" }
        $Total.Value += $count
    }
}

function Process-CurrentLog {
    param([string]$XPath,[string]$OutFolder,[ref]$Total,[ref]$Consolidated)

    Write-Info "[Processing Current Security Log]"
    $labelCur="[Processing Current Security Log]"
    Write-ProgressNote -activity $labelCur -status "Scanning..." -percent 5

    $currentFound=@()
    $fetchCur = Fetch-EventsSafe -SourceType 'Current' -XPath $XPath
    if($fetchCur.Error){
        Write-Red ("Error reading current Security log: {0}" -f $fetchCur.Error.Message)
    }else{
        $cnt=0
        foreach($ev in $fetchCur.Events){
            $cnt++
            if($cnt % 100 -eq 0){ $pct=[math]::Min(95,[int](5+($cnt%2000)/20)); Write-ProgressNote -activity $labelCur -status "Scanning... ($cnt events matched)" -percent $pct }
            $row=Select-EventFields -ev $ev
            $row.Source='CurrentLog'
            $currentFound += $row
            $Consolidated.Value += $row
        }
    }
    Write-ProgressNote -activity $labelCur -status "Finalizing..." -percent 100
    Write-Progress -Activity $labelCur -Completed

    $curCount=$currentFound.Count
    if($curCount -gt 0){ Write-Green ("[########################################] 100% Done          Total: {0} √" -f $curCount) }
    else{ Write-Info  ("[########################################] 100% Done          Total: {0} √" -f $curCount) }

    $curName="ADUserAudit-Current-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $curOut=Join-Path $OutFolder $curName
    try{
        $currentFound | Select-Object Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source |
            Export-Csv -LiteralPath $curOut -NoTypeInformation -Encoding UTF8
        Write-Green "✓ $curOut  ($curCount rows)`n"
    }catch{ Write-Red "Failed to export CSV for current log - $($_.Exception.Message)" }
    $Total.Value += $curCount
}

# ---------------- Run with correct order ----------------
$totalCount=0
$consolidatedBuffer=@()

if($logSel -eq '1'){
    # current only
    Process-CurrentLog -XPath $xpath -OutFolder $outFolder -Total ([ref]$totalCount) -Consolidated ([ref]$consolidatedBuffer)
}else{
    if($processCurrentFirst){
        # Newest → Oldest: current first, then files (newest→oldest already sorted above)
        Process-CurrentLog  -XPath $xpath -OutFolder $outFolder -Total ([ref]$totalCount) -Consolidated ([ref]$consolidatedBuffer)
        Process-ArchivedFiles -Files $fileList -XPath $xpath -OutFolder $outFolder -Total ([ref]$totalCount) -Consolidated ([ref]$consolidatedBuffer)
    }else{
        # Oldest → Newest: files first, then current
        Process-ArchivedFiles -Files $fileList -XPath $xpath -OutFolder $outFolder -Total ([ref]$totalCount) -Consolidated ([ref]$consolidatedBuffer)
        Process-CurrentLog  -XPath $xpath -OutFolder $outFolder -Total ([ref]$totalCount) -Consolidated ([ref]$consolidatedBuffer)
    }
}

# ---------------- Optional consolidated ----------------
Write-Info "Per-file exports completed."
Write-Info ("Grand total (archived + current): {0}" -f $totalCount)
$ansCons=(Read-Host "Also create consolidated CSV at the end? (Y/N)").Trim().ToUpper()

if($ansCons -eq 'Y'){
    try{
        $consName="ADUserAudit-Consolidated-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
        $consOut=Join-Path $outFolder $consName
        $consolidatedBuffer | Select-Object Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source |
            Export-Csv -LiteralPath $consOut -NoTypeInformation -Encoding UTF8
        Write-Info "[Consolidated Export]"
        Write-Info "✓ $consOut  (Total rows: $($consolidatedBuffer.Count))"
    }catch{ Write-Red "Failed to export consolidated CSV - $($_.Exception.Message)" }
}

Write-Info ""
Write-Info "Summary per file completed."
Write-Info ("Total records across archived + current: {0}" -f $totalCount)
