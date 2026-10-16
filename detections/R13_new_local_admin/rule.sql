-- R13: an account is created (4720) and added to Administrators (4732) on the same host
-- within an hour. The 4732 record names the member by SID (MemberSid), which matches the new
-- account's TargetSid; the group is Administrators by its well-known SID S-1-5-32-544.
SELECT
    g.ts,
    g.dataset,
    g.host_name,
    c.user_name,
    printf('Account %s created and added to Administrators within an hour', c.user_name)
        AS summary,
    [c.event_id, g.event_id] AS event_ids
FROM events c
JOIN events g
  ON g.dataset = c.dataset AND g.host_name = c.host_name
 AND (g.raw ->> 'MemberSid') = (c.raw ->> 'TargetSid')
 AND g.ts BETWEEN c.ts AND c.ts + INTERVAL 1 HOUR
WHERE c.source = 'winsec' AND c.event_code = '4720'
  AND g.source = 'winsec' AND g.event_code = '4732'
  AND (g.raw ->> 'TargetSid') = 'S-1-5-32-544'
