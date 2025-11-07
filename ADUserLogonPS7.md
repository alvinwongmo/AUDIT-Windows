<#
ADUserLogon (DC-auth only) - PowerShell 7

Scopes:
1) Successful authentication = 4768 + 4776(success)
2) Failed    authentication = 4771 + 4776(failure)
3) Successful + Failed

CSV columns (fixed order):
Timestamp, EventID, EventName, Account, ClientAddress, Workstation, StatusText, SourceFile

Behavior:
- Default CSV folder = script directory (no 'out' subfolder)
- Only process files named: Archive-Security-YYYY-MM-DD-HH-MM-SS-fff.evtx
- For "Newest → Oldest", process the Current Security Log first, then archived files (newest→oldest)
- Even when a file/current log yields 0 rows, export an empty CSV and print green "✓ ... (0 rows)"
- Strict date input YYYY-MM-DD; End date ENTER = today; future dates and start> end rejected
- User list is REQUIRED: prompt for absolute path; default = scriptDir\userlist.txt

Notes:
- 4776 success/failure determined by Status == '0x0' (success); XPath filters by EventID, split done in PowerShell
- StatusText maps common codes; unknown codes show as Unknown(<hex>)
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
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        $isAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $elrSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-573') # Event Log Readers
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

# ---------------- StatusText helper ----------------
function Get-StatusText([string]$eventId,[string]$statusHex){
    if([string]::IsNullOrWhiteSpace($statusHex)){ return $null }
    $hex = $statusHex
    switch -Regex ($hex){
        '^0x0$'           { return 'Success' }
        '^0x18$'          { return 'Bad password' }
        '^0x12$'          { return 'Account disabled' }
        '^0x19$'          { return 'No such user' }
        '^0x23$'          { return 'Password must change' }
        '^0xC000006A$'    { return 'Username OK, bad password' }
        '^0xC000006D$'    { return 'Logon failure' }
        '^0xC000006F$'    { return 'Logon time restriction' }
        '^0xC0000070$'    { return 'Workstation restriction' }
        '^0xC0000071$'    { return 'Password expired' }
        '^0xC0000234$'    { return 'Account locked out' }
        default           { return "Unknown($hex)" }
    }
}

# ---------------- Event mappers ----------------
function Get-EventName([int]$id){
    switch($id){
        4768 {'Kerberos TGT Request'}
        4771 {'Kerberos PreAuth Failure'}
        4776 {'NTLM Authentication'}
        default {"Event $id"}
    }
}

# Extract fields for ADUserLogon CSV
function Select-LogonFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)

    $id = [int]$ev.Id
    $tsLocal = ($ev.TimeCreated).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $xml = [xml]$ev.ToXml()
    $dataNodes = $xml.Event.EventData.Data

    $getVal = {
        param($name)
        foreach ($n in $dataNodes) { if ($n.Name -eq $name) { return [string]$n.'#text' } }
        return $null
    }

    # account fields may vary by event
    $account = (& $getVal 'TargetUserName')
    if(-not $account){ $account = (& $getVal 'AccountName') }
    if(-not $account){ $account = (& $getVal 'TargetUserSid') }

    # client / workstation
    $clientIp = (& $getVal 'IpAddress')
    if(-not $clientIp){ $clientIp = (& $getVal 'ClientAddress') }
    $workst   = (& $getVal 'WorkstationName')

    # status code for mapping and 4776 success/fail split
    $status = (& $getVal 'Status')
    if(-not $status){ $status = (& $getVal 'FailureCode') } # 4771
    $statusText = Get-StatusText -eventId $id -statusHex $status

    [pscustomobject]@{
        Timestamp    = $tsLocal
        EventID      = $id
        EventName    = (Get-EventName $id)
        Account      = $account
        ClientAddress= $clientIp
        Workstation  = $workst
        StatusText   = $statusText
        SourceFile   = ''   # set by caller
        _StatusRaw   = $status # internal (do not export)
    }
}

# ---------------- XPath builder ----------------
function Build-XPath([int[]]$ids,[datetime]$start,[datetime]$end,[string[]]$users){
    $startUtc=$start.ToUniversalTime().ToString('o')
    $endUtc=$end.AddDays(1).AddMilliseconds(-1).ToUniversalTime().ToString('o')
    $idPart=($ids|ForEach-Object{"EventID=$_"} ) -join ' or '
    $base="*[System[($idPart) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"
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

# ---------------- File time window (skip non-overlap) ----------------
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
        return [pscustomobject]@{ Events=@($evs); Error=$null }
    }catch{
        $msg = $_.Exception.Message
        if($msg -match 'No events were found that match the specified selection criteria'){
            return [pscustomobject]@{ Events=@(); Error=$null } # treat as 0 rows (not an error)
        } else {
            return [pscustomobject]@{ Events=@(); Error=$_.Exception }
        }
    }
}

# ---------------- Banner & privilege ----------------
Write-Info "# ======================="
Write-Info "# AD User Logon Audit (DC-auth only)"
Write-Info "# PowerShell 7"
Write-Info "# =======================`n"

if(-not (Test-AdminOrELR)){
    Write-Red "[Privilege Check] Insufficient privileges. Run as Administrator or a member of 'Event Log Readers'."
    exit 1
}
Write-Info "[Privilege Check]"
Write-Info "✓ You are running with sufficient privileges (Administrators/Event Log Readers).`n"

# ---------------- Scope menu ----------------
Write-Info "[Main Menu - Event Scope]"
Write-Info "1) Successful authentication (4768 + 4776-success)"
Write-Info "2) Failed    authentication (4771 + 4776-failure)"
Write-Info "3) Successful + Failed"
$scopeSel=Read-Host "Selection"

# event sets (query 4776 then split by status)
[int[]]$idsToQuery=@()
$want4768=$false; $want4771=$false; $want4776Success=$false; $want4776Failure=$false
switch($scopeSel){
    '1' { $idsToQuery=@(4768,4776); $want4768=$true; $want4776Success=$true }
    '2' { $idsToQuery=@(4771,4776); $want4771=$true; $want4776Failure=$true }
    '3' { $idsToQuery=@(4768,4771,4776); $want4768=$true; $want4771=$true; $want4776Success=$true; $want4776Failure=$true }
    default { Write-Red "Invalid selection."; exit 1 }
}

# ---------------- User list (REQUIRED) ----------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$defaultUserList = Join-Path $scriptDir 'userlist.txt'
Write-Info "[User List]"
Write-Host ("Enter absolute path to user list (default: {0})" -f $defaultUserList)
Write-Host "> " -NoNewline
$userListPath = Read-Host
if([string]::IsNullOrWhiteSpace($userListPath)){ $userListPath = $defaultUserList }
$isAbs = ($userListPath -match '^[a-zA-Z]:\\') -or ($userListPath -match '^\\\\')
if(-not $isAbs){ Write-Red "Path must be an absolute path: '$userListPath'"; exit 1 }
if(-not (Test-Path -LiteralPath $userListPath)){ Write-Red "User list not found: $userListPath"; exit 1 }
$raw = Get-Content -LiteralPath $userListPath -ErrorAction Stop
$users = $raw | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
if(-not $users -or $users.Count -eq 0){ Write-Red "User list is empty."; exit 1 }
Write-Info ("✓ Loaded accounts: {0}`n" -f ($users -join ', '))

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

        # coverage & overlap
        $windows=@()
        foreach($fItem in $archCandidates){
            $w=Get-FileTimeWindow -path $fItem.FullName
            if($w.Valid){ $windows+=$w }
        }
        $overlap=$windows | Where-Object { $_.Start -le $endDate -and $_.End -ge $startDate }
        if($overlap.Count -gt 0){
            $covStart=($overlap|Measure-Object -Property Start -Minimum).Minimum
            $covEnd  =($overlap|Measure-Object -Property End   -Maximum).Maximum
            Write-Info "✓ Actual searchable coverage: $($covStart.ToString('yyyy-MM-dd')) ~ $($covEnd.ToString('yyyy-MM-dd'))"
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
    $processCurrentFirst=$true
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
    Write-Info "  - Archived EVTX → ADUserLogon-<yyyyMMdd>-<index>.csv"
    Write-Info "  - Current       → ADUserLogon-Current-<yyyyMMdd-HHmmss>.csv"
    Write-Host ""
}catch{ Write-Red $_.Exception.Message; exit 1 }

# ---------------- Build query ----------------
$users = $users | Select-Object -Unique
$xpath = Build-XPath -ids $idsToQuery -start $startDate -end $endDate -users $users

# ---------------- Filters by scope (after fetch) ----------------
function Match-Scope {
    param(
        [pscustomobject]$Row,
        [bool]$want4768,[bool]$want4771,[bool]$want476Success,[bool]$want476Failure
    )
    switch([int]$Row.EventID){
        4768 { return $want4768 } # success
        4771 { return $want4771 } # failure
        4776 {
            $s = ($Row._StatusRaw)
            if([string]::IsNullOrWhiteSpace($s)){ return $true } # rare; treat as included
            if($s -eq '0x0'){ return $want476Success } else { return $want476Failure }
        }
        default { return $false }
    }
}

# ---------------- Core processors ----------------
function Export-Rows {
    param([pscustomobject[]]$Rows,[string]$OutPath)
    $Rows | Select-Object Timestamp,EventID,EventName,Account,ClientAddress,Workstation,StatusText,SourceFile |
        Export-Csv -LiteralPath $OutPath -NoTypeInformation -Encoding UTF8
}

function Process-ArchivedFiles {
    param([string[]]$Files,[string]$XPath,[string]$OutFolder,
          [bool]$want4768,[bool]$want4771,[bool]$want476Success,[bool]$want476Failure,
          [ref]$GrandTotal,[ref]$Consolidated)

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
            if($cnt % 80 -eq 0){ $pct=[math]::Min(95,[int](5+($cnt%1600)/16)); Write-ProgressNote -activity $label -status "Scanning... ($cnt events read)" -percent $pct }
            $row=Select-LogonFields -ev $ev
            if( Match-Scope -Row $row -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure ){
                $row.SourceFile = $fileShort
                $found += $row
                $Consolidated.Value += $row
            }
        }
        Write-ProgressNote -activity $label -status "Finalizing..." -percent 100
        Write-Progress -Activity $label -Completed

        $count=$found.Count
        if($count -gt 0){ Write-Green ("[########################################] 100% Done          Total: {0} √" -f $count) }
        else{ Write-Info  ("[########################################] 100% Done          Total: {0} √" -f $count) }

        $dateTag=(Get-Item -LiteralPath $f).LastWriteTime.ToString('yyyyMMdd')
        $outFile=Join-Path $OutFolder ("ADUserLogon-{0}-{1}.csv" -f $dateTag,$idx)
        try{
            Export-Rows -Rows $found -OutPath $outFile
            Write-Green "✓ $outFile  ($count rows)`n"
        }catch{ Write-Red "Failed to export CSV for $f - $($_.Exception.Message)" }
        $GrandTotal.Value += $count
    }
}

function Process-CurrentLog {
    param([string]$XPath,[string]$OutFolder,
          [bool]$want4768,[bool]$want4771,[bool]$want476Success,[bool]$want476Failure,
          [ref]$GrandTotal,[ref]$Consolidated)

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
            if($cnt % 120 -eq 0){ $pct=[math]::Min(95,[int](5+($cnt%2400)/24)); Write-ProgressNote -activity $labelCur -status "Scanning... ($cnt events read)" -percent $pct }
            $row=Select-LogonFields -ev $ev
            if( Match-Scope -Row $row -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure ){
                $row.SourceFile='CurrentLog'
                $currentFound += $row
                $Consolidated.Value += $row
            }
        }
    }
    Write-ProgressNote -activity $labelCur -status "Finalizing..." -percent 100
    Write-Progress -Activity $labelCur -Completed

    $curCount=$currentFound.Count
    if($curCount -gt 0){ Write-Green ("[########################################] 100% Done          Total: {0} √" -f $curCount) }
    else{ Write-Info  ("[########################################] 100% Done          Total: {0} √" -f $curCount) }

    $curName="ADUserLogon-Current-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $curOut=Join-Path $OutFolder $curName
    try{
        Export-Rows -Rows $currentFound -OutPath $curOut
        Write-Green "✓ $curOut  ($curCount rows)`n"
    }catch{ Write-Red "Failed to export CSV for current log - $($_.Exception.Message)" }

    $GrandTotal.Value += $curCount
}

# ---------------- Run with order rules ----------------
$totalCount=0
$consolidated=@()

if($logSel -eq '1'){
    Process-CurrentLog -XPath $xpath -OutFolder $outFolder -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure -GrandTotal ([ref]$totalCount) -Consolidated ([ref]$consolidated)
}else{
    if($processCurrentFirst){
        # Newest → Oldest: current first, then archived (already sorted newest→oldest)
        Process-CurrentLog    -XPath $xpath -OutFolder $outFolder -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure -GrandTotal ([ref]$totalCount) -Consolidated ([ref]$consolidated)
        Process-ArchivedFiles -Files $fileList -XPath $xpath -OutFolder $outFolder -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure -GrandTotal ([ref]$totalCount) -Consolidated ([ref]$consolidated)
    }else{
        # Oldest → Newest: archived first, then current
        Process-ArchivedFiles -Files $fileList -XPath $xpath -OutFolder $outFolder -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure -GrandTotal ([ref]$totalCount) -Consolidated ([ref]$consolidated)
        Process-CurrentLog    -XPath $xpath -OutFolder $outFolder -want4768:$want4768 -want4771:$want4771 -want476Success:$want476Success -want476Failure:$want476Failure -GrandTotal ([ref]$totalCount) -Consolidated ([ref]$consolidated)
    }
}

# ---------------- Optional consolidated ----------------
Write-Info "Per-file exports completed."
Write-Info ("Grand total (archived + current): {0}" -f $totalCount)
$ansCons=(Read-Host "Also create consolidated CSV at the end? (Y/N)").Trim().ToUpper()

if($ansCons -eq 'Y'){
    try{
        $consName="ADUserLogon-Consolidated-{0}.csv" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
        $consOut=Join-Path $outFolder $consName
        $consolidated | Select-Object Timestamp,EventID,EventName,Account,ClientAddress,Workstation,StatusText,SourceFile |
            Export-Csv -LiteralPath $consOut -NoTypeInformation -Encoding UTF8
        Write-Info "[Consolidated Export]"
        Write-Info "✓ $consOut  (Total rows: $($consolidated.Count))"
    }catch{ Write-Red "Failed to export consolidated CSV - $($_.Exception.Message)" }
}

Write-Info ""
Write-Info "Summary per file completed."
Write-Info ("Total records across archived + current: {0}" -f $totalCount)
