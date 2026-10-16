-- R07: a new scheduled task (Security 4698), or schtasks.exe /create (Sysmon 1 or 4688),
-- unless the task is one of Windows' own (\Microsoft\...) or OneDrive's updater.
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
        AND NOT regexp_matches(coalesce(task_name, ''), '(?i)^\\(Microsoft\\|OneDrive )')
    )
   OR (
        ((source = 'sysmon' AND event_code = '1') OR (source = 'winsec' AND event_code = '4688'))
        AND process_name = 'schtasks.exe'
        AND regexp_matches(process_command_line, '(?i)\s[/-]create\b')
        AND NOT regexp_matches(process_command_line, '(?i)[/-]tn\s+"?\\?(Microsoft\\|OneDrive )')
    )
