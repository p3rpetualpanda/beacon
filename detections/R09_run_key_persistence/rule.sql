-- R09: a registry value is set under ...\CurrentVersion\Run (or RunOnce, RunServices,
-- RunServicesOnce), so a program starts at every logon (Sysmon 13).
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('%s set Run key %s to %s', process_name, registry_path, left(registry_value, 100))
        AS summary,
    [event_id] AS event_ids
FROM events
WHERE source = 'sysmon' AND event_code = '13'
  AND regexp_matches(registry_path, '(?i)\\CurrentVersion\\(Run|RunOnce|RunServices|RunServicesOnce)\\')
  -- Tuned: Defender and Teams rewrite their own Run values on update. Both the process and
  -- the value name must match, so a renamed binary writing another value still alerts.
  AND NOT (process_name = 'msmpeng.exe' AND registry_path ILIKE '%\Run\WindowsDefender')
  AND NOT (process_name = 'teams.exe' AND registry_path ILIKE '%\Run\com.squirrel.Teams.Teams')
