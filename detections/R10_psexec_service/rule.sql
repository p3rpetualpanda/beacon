-- R10: a new service (System 7045 or Security 4697) named or built like PsExec and its clones.
-- The name is matched, so a renamed copy is missed; R08 still catches a user-writable path.
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('PsExec-style service %s installed (%s)', service_name, left(service_path, 120)) AS summary,
    [event_id] AS event_ids
FROM events
WHERE ((source = 'system' AND event_code = '7045') OR (source = 'winsec' AND event_code = '4697'))
  AND regexp_matches(coalesce(service_name, '') || ' ' || coalesce(service_path, ''), '(?i)(psexe(c|svc)|paexe(c|svc)|remcom|csexec)')
  -- Tuned: a 4697 that repeats a 7045 for the same path within 5 s adds nothing; keep the 7045.
  AND NOT (
      source = 'winsec' AND EXISTS (
          SELECT 1 FROM events s
          WHERE s.source = 'system' AND s.event_code = '7045'
            AND s.dataset = events.dataset AND s.host_name = events.host_name
            AND s.service_path = events.service_path
            AND s.ts BETWEEN events.ts - INTERVAL 5 SECOND AND events.ts + INTERVAL 5 SECOND
            AND regexp_matches(coalesce(s.service_name, '') || ' ' || coalesce(s.service_path, ''),
                               '(?i)(psexe(c|svc)|paexe(c|svc)|remcom|csexec)')
      )
  )
