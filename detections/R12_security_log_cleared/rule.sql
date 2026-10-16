-- R12: the Security event log is cleared (Security 1102).
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('Security log cleared on %s by %s', host_name, coalesce(user_name, 'unknown'))
        AS summary,
    [event_id] AS event_ids
FROM events
WHERE source = 'winsec' AND event_code = '1102'
