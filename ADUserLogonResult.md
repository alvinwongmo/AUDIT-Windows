# =======================
# AD User Logon Audit (DC-auth only)
# PowerShell 5.1
# =======================

[Privilege Check]
✓ You are running with sufficient privileges (Administrators/Event Log Readers).

[Main Menu - Event Scope]
1) Successful authentication (4768 + 4776-success)
2) Failed    authentication (4771 + 4776-failure)
3) Successful + Failed
Selection: 3
✓ You selected: Successful + Failed

[User List]
Enter absolute path to user list (default: C:\Users\alvinwong\Desktop\script\userlist.txt)
> (ENTER)
✓ Loaded accounts: alvinwong, test.user, backup01

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
> D:\Logs\
✓ Discovered 4 Archive-Security-*.evtx files
✓ Actual searchable coverage: 2025-10-01 ~ 2025-11-07
Process order:
1) Oldest → Newest
2) Newest → Oldest  (Current log will be processed FIRST)
Selection: 2

[Export Settings]
CSV output folder (absolute path; default = C:\Users\alvinwong\Desktop\script\):
> (ENTER)
✓ Per-file export is enabled. File naming:
  - Archived EVTX → ADUserLogon-<yyyyMMdd>-<index>.csv
  - Current       → ADUserLogon-Current-<yyyyMMdd-HHmmss>.csv

[Processing Current Security Log]
[########################################] 100% Done          Total: 1 √
✓ C:\Users\alvinwong\Desktop\script\ADUserLogon-Current-20251107-193202.csv  (1 rows)

[Processing 1/3]  Archive-Security-2025-11-01-00-00-00-000.evtx
[########################################] 100% Done          Total: 2 √
✓ C:\Users\alvinwong\Desktop\script\ADUserLogon-20251101-1.csv  (2 rows)

[Processing 2/3]  Archive-Security-2025-10-30-08-13-56-309.evtx
[########################################] 100% Done          Total: 0 √
✓ C:\Users\alvinwong\Desktop\script\ADUserLogon-20251030-2.csv  (0 rows)

[Processing 3/3]  Archive-Security-2025-10-01-00-00-00-000.evtx
[########################################] 100% Done          Total: 1 √
✓ C:\Users\alvinwong\Desktop\script\ADUserLogon-20251001-3.csv  (1 rows)

Per-file exports completed.
Grand total (archived + current): 4
Also create consolidated CSV at the end? (Y/N): Y
[Consolidated Export]
✓ C:\Users\alvinwong\Desktop\script\ADUserLogon-Consolidated-20251107-193202.csv  (Total rows: 4)

ADUserLogon-Current-20251107-193202.csv
Timestamp,EventID,EventName,Account,ClientAddress,Workstation,StatusText,SourceFile
2025-11-07 07:45:10,4776,NTLM Authentication,alvinwong,,DC01,Success,CurrentLog

ADUserLogon-20251101-1.csv
Timestamp,EventID,EventName,Account,ClientAddress,Workstation,StatusText,SourceFile
2025-11-01 02:03:21,4768,Kerberos TGT Request,alvinwong,10.0.2.15,,Success,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-01 22:43:10,4771,Kerberos PreAuth Failure,backup01,10.0.3.10,,Bad password,Archive-Security-2025-11-01-00-00-00-000.evtx

ADUserLogon-Consolidated-20251107-193202.csv（整合檔）
Timestamp,EventID,EventName,Account,ClientAddress,Workstation,StatusText,SourceFile
2025-10-01 06:20:45,4776,NTLM Authentication,test.user,,DC01,Success,Archive-Security-2025-10-01-00-00-00-000.evtx
2025-11-01 02:03:21,4768,Kerberos TGT Request,alvinwong,10.0.2.15,,Success,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-01 22:43:10,4771,Kerberos PreAuth Failure,backup01,10.0.3.10,,Bad password,Archive-Security-2025-11-01-00-00-00-000.evtx
2025-11-07 07:45:10,4776,NTLM Authentication,alvinwong,,DC01,Success,CurrentLog
