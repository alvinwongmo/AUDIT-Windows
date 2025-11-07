效果:
[Privilege Check]
✓ You are running with sufficient privileges (Administrators/Event Log Readers).

[Main Menu - Event Scope]
1) Successful authentication (4768 + 4776-success)
2) Failed authentication (4771 + 4776-failure)
3) Successful + Failed
Selection: 3

[User List]
Enter absolute path to user list (default: C:\AuditTools\AD_Deprov\userlist.txt):
> (ENTER)
✓ Loaded accounts: alice.wu, b.lam, cheng.lee, d.ng

[Period]
1) 1 day   2) 1 week   3) 1 month   4) 1 quarter   5) 1 year   6) Custom range
Selection: 6
Start date (YYYY-MM-DD): 2025-01-01
End date   (YYYY-MM-DD) [ENTER = today]: (ENTER)
✓ Parsed range: 2025-01-01 ~ 2025-11-07 (inclusive)

[Log Sources]
1) Current Security log only
2) Current Security + Archived EVTX
Selection: 2
Archived EVTX folder (absolute path; default = script directory):
> D:\SecLogs
✓ Discovered 9 Archive-Security-*.evtx files
✓ Actual searchable coverage: 2025-09-01 ~ 2025-11-07
Process order:
1) Oldest → Newest
2) Newest → Oldest
Selection: 1

[Export Settings]
CSV output folder (absolute path; default = C:\AuditTools\AD_Deprov\):
> (ENTER)
✓ Per-file export is enabled. File naming:
  - Archived EVTX → ADUserLogon-<yyyyMMdd>-<index>.csv
  - Current       → ADUserLogon-Current-<yyyyMMdd-HHmmss>.csv

[Processing 1/5]  Archive-Security-2025-09-01-00-00-00-000.evtx
[########################################] 100% Done          Total: 12 √
→ Exporting CSV...
✓ C:\AuditTools\AD_Deprov\ADUserLogon-20250901-1.csv  (12 rows)

[Processing 2/5]  Archive-Security-2025-09-12-00-00-00-000.evtx
[########################################] 100% Done          Total: 3  √
→ Exporting CSV...
✓ C:\AuditTools\AD_Deprov\ADUserLogon-20250912-2.csv  (3 rows)

[Processing 3/5]  Archive-Security-2025-10-03-00-00-00-000.evtx
[########################################] 100% Done          Total: 9  √
→ Exporting CSV...
✓ C:\AuditTools\AD_Deprov\ADUserLogon-20251003-3.csv  (9 rows)

[Processing 4/5]  Archive-Security-2025-10-31-00-00-00-000.evtx
[########################################] 100% Done          Total: 1  √
→ Exporting CSV...
✓ C:\AuditTools\AD_Deprov\ADUserLogon-20251031-4.csv  (1 row)

[Processing Current Security Log]
[########################################] 100% Done          Total: 5  √
→ Exporting CSV...
✓ C:\AuditTools\AD_Deprov\ADUserLogon-Current-20251107-142305.csv  (5 rows)

Per-file exports completed.
Grand total (archived + current): 30
Also create consolidated CSV at the end? (Y/N): Y
Also create per-account summary CSV? (Y/N): Y

[Consolidated Export]
✓ C:\AuditTools\AD_Deprov\ADUserLogon-Consolidated-20251107-142305.csv  (Total rows: 30)

[Per-Account Summary]
✓ C:\AuditTools\AD_Deprov\ADUserLogon-AccountSummary-20251107-142305.csv
