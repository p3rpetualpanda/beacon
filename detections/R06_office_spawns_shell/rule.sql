-- R06: an Office application is the parent of a shell or script host (Sysmon 1 or 4688).
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('%s started %s: %s', parent_process_name, process_name,
           left(process_command_line, 120)) AS summary,
    [event_id] AS event_ids
FROM events
WHERE ((source = 'sysmon' AND event_code = '1') OR (source = 'winsec' AND event_code = '4688'))
  AND parent_process_name IN ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
  AND process_name IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
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
