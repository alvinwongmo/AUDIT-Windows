# =======================
# AD User Account Management Audit
# PowerShell 7 (Windows)
# =======================

[Privilege Check]
✓ You are running with sufficient privileges (Administrators/Event Log Readers).

[Main Menu - Event Scope]
1) Account created   (4720)
2) Account enabled   (4722)
3) Account disabled  (4725)
4) Account deleted   (4726)
5) Account Created + Deleted      (4720+4726)
6) Account Enabled + Disabled     (4722+4725)
7) All of the above               (4720+4722+4725+4726)
Selection: 6
✓ You selected: Account Enabled + Disabled (4722,4725)

[User List]
1) All users (no filtering)
2) Load from userlist.txt (absolute path)
Selection: 2
Enter absolute path to user list (default: C:\Scripts\userlist.txt):
> (ENTER)
✓ Loaded accounts: alvinwong, svc.backup02, alice.chan

[Period]
1) 1 day   2) 1 week   3) 1 month   4) 1 quarter   5) 1 year   6) Custom range
Selection: 6
Start date (YYYY-MM-DD): 2025-10-01
End date   (YYYY-MM-DD) [ENTER = today]: (ENTER)
✓ Parsed range: 2025-10-01 ~ 2025-11-07 (inclusive)

[Log Sources]
1) Current Security log only
2) Current Security + Archived EVTX
Selection: 2
Archived EVTX folder (absolute path; default = script directory):
> D:\SecLogs\
✓ Discovered 6 Archive-Security-*.evtx files
✓ Actual searchable coverage: 2025-10-01 ~ 2025-11-07
Process order:
1) Oldest → Newest
2) Newest → Oldest  (Current log will be processed FIRST)
Selection: 2

[Export Settings]
CSV output folder (absolute path; default = C:\Scripts\):
> (ENTER)
✓ Per-file export is enabled. File naming:
  - Archived EVTX → ADUserAudit-<yyyyMMdd>-<index>.csv
  - Current       → ADUserAudit-Current-<yyyyMMdd-HHmmss>.csv

[Processing Current Security Log]
[########################################] 100% Done          Total: 1 √
✓ C:\Scripts\ADUserAudit-Current-20251107-164015.csv  (1 rows)

[Processing 1/4]  Archive-Security-2025-11-01-00-00-00-000.evtx
[########################################] 100% Done          Total: 2 √
✓ C:\Scripts\ADUserAudit-20251101-1.csv  (2 rows)

[Processing 2/4]  Archive-Security-2025-10-30-08-13-56-309.evtx
[########################################] 100% Done          Total: 0 √
✓ C:\Scripts\ADUserAudit-20251030-2.csv  (0 rows)

[Processing 3/4]  Archive-Security-2025-10-24-00-00-00-000.evtx
[########################################] 100% Done          Total: 1 √
✓ C:\Scripts\ADUserAudit-20251024-3.csv  (1 rows)

[Processing 4/4]  Archive-Security-2025-10-01-00-00-00-000.evtx
[########################################] 100% Done          Total: 1 √
✓ C:\Scripts\ADUserAudit-20251001-4.csv  (1 rows)

Per-file exports completed.
Grand total (archived + current): 5
Also create consolidated CSV at the end? (Y/N): Y

[Consolidated Export]
✓ C:\Scripts\ADUserAudit-Consolidated-20251107-164015.csv  (Total rows: 5)

ADUserAudit-Current-20251107-164015.csv
Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source
2025-11-07 07:45:10,4725,Disabled,svc.backup02,security.admin,CurrentLog

ADUserAudit-20251101-1.csv
Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source
2025-11-01 03:14:19,4722,Enabled,alvinwong,administrator,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-01 22:43:10,4725,Disabled,svc.backup02,ops.lead,Archive-Security-2025-11-01-00-00-00-000.evtx

ADUserAudit-Consolidated-20251107-164015.csv（節錄）
Timestamp,EventID,Action,TargetUserName,SubjectUserName,Source
2025-10-01 08:02:55,4725,Disabled,svc.backup02,helpdesk.tam,Archive-Security-2025-10-01-00-00-00-000.evtx
2025-10-24 21:09:42,4722,Enabled,alice.chan,administrator,Archive-Security-2025-10-24-00-00-00-000.evtx
2025-11-01 03:14:19,4722,Enabled,alvinwong,administrator,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-01 22:43:10,4725,Disabled,svc.backup02,ops.lead,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-07 07:45:10,4725,Disabled,svc.backup02,security.admin,CurrentLog
