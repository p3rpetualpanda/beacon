-- R08: a new service (System 7045 or Security 4697) whose binary is in a user-writable folder.
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('Service %s installed from %s', service_name, left(service_path, 120)) AS summary,
    [event_id] AS event_ids
FROM events
WHERE ((source = 'system' AND event_code = '7045') OR (source = 'winsec' AND event_code = '4697'))
  AND regexp_matches(service_path, '(?i)(\\users\\|\\temp\\|\\appdata\\|\\programdata\\|\\perflogs\\|%temp%|%appdata%|%localappdata%|%programdata%|%public%)')
