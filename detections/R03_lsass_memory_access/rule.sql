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
  AND (try_cast(granted_access AS BIGINT) & 16) <> 0
  -- Allow Windows' own processes only from their real folders, so a renamed tool such as
  -- C:\Users\Public\svchost.exe still alerts.
  AND NOT (
      process_name IN ('csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe',
                       'svchost.exe', 'wmiprvse.exe')
      AND regexp_matches(process_path, '(?i)^c:\\windows\\system32\\(wbem\\)?[^\\]+$')
  )
  AND NOT (
      process_name = 'msmpeng.exe'
      AND regexp_matches(process_path,
                         '(?i)^c:\\(programdata\\microsoft|program files)\\windows defender\\')
  )
