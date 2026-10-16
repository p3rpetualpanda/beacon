-- R07: a new scheduled task (Security 4698), or schtasks.exe /create (Sysmon 1 or 4688),
-- except OneDrive's own updater. Tasks under \Microsoft\ still alert: attackers hide them there.
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    CASE WHEN event_code = '4698'
         THEN printf('Scheduled task %s registered', task_name)
         ELSE printf('schtasks.exe created a task: %s', left(process_command_line, 120))
    END AS summary,
    [event_id] AS event_ids
FROM events
WHERE (
        source = 'winsec' AND event_code = '4698'
        AND NOT regexp_matches(coalesce(task_name, ''), '(?i)^\\OneDrive Standalone Update Task-')
    )
   OR (
        ((source = 'sysmon' AND event_code = '1') OR (source = 'winsec' AND event_code = '4688'))
        AND process_name = 'schtasks.exe'
        AND regexp_matches(process_command_line, '(?i)\s[/-]create\b')
    )
  -- Tuned: when Sysmon and Security both log the same launch, keep only the Sysmon record.
  AND NOT (
      source = 'winsec' AND EXISTS (
          SELECT 1 FROM events s
          WHERE s.source = 'sysmon' AND s.event_code = '1'
            AND s.dataset = events.dataset AND s.host_name = events.host_name
            AND s.process_command_line = events.process_command_line
            AND s.ts BETWEEN events.ts - INTERVAL 5 SECOND AND events.ts + INTERVAL 5 SECOND
      )
  )
