-- R05: PowerShell started with -EncodedCommand, or any prefix of it PowerShell accepts
-- (-e, -en, -enc, ...) or -ec, followed by a base64 payload. Sysmon 1 or Security 4688.
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('%s ran an encoded command: %s', process_name, left(process_command_line, 120))
        AS summary,
    [event_id] AS event_ids
FROM events
WHERE ((source = 'sysmon' AND event_code = '1') OR (source = 'winsec' AND event_code = '4688'))
  AND process_name IN ('powershell.exe', 'pwsh.exe')
  AND regexp_matches(process_command_line, '(?i)\s[-/\x{2013}\x{2014}](ec|e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["'']?[A-Za-z0-9+/=]{20,}')
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
