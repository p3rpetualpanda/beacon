-- R03: a process other than Windows' own system processes opens lsass.exe (Sysmon 10)
-- with PROCESS_VM_READ (0x10) in the granted access mask, which credential dumping needs.
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('%s opened lsass.exe with access %s', process_name, granted_access) AS summary,
    [event_id] AS event_ids
FROM events
WHERE source = 'sysmon' AND event_code = '10'
  AND target_process_name = 'lsass.exe'
  AND (try_cast(granted_access AS INTEGER) & 16) <> 0
  AND coalesce(process_name, '') NOT IN (
      'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe',
      'svchost.exe', 'msmpeng.exe', 'wmiprvse.exe'
  )
