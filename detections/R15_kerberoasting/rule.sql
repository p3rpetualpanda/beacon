-- R15: one user gets RC4 service tickets for 3+ different services in 5 minutes (Security 4769).
-- Machine accounts (ending in $) and krbtgt are left out; they are not crackable targets.
WITH tickets AS (
    SELECT event_id, ts, dataset, host_name, user_name, json_extract_string(raw, '$.ServiceName') AS service
    FROM events
    WHERE source = 'winsec' AND event_code = '4769'
      AND json_extract_string(raw, '$.TicketEncryptionType') IN ('0x17', '0x18')
      AND json_extract_string(raw, '$.Status') = '0x0'
      AND json_extract_string(raw, '$.ServiceName') NOT LIKE '%$'
      AND lower(json_extract_string(raw, '$.ServiceName')) <> 'krbtgt'
),
bursts AS (
    SELECT
        *,
        count(DISTINCT service) OVER w AS services_5m,
        list(DISTINCT service) OVER w  AS services,
        list(event_id) OVER w          AS ids
    FROM tickets
    WINDOW w AS (
        PARTITION BY dataset, host_name, user_name ORDER BY ts
        RANGE BETWEEN INTERVAL 5 MINUTE PRECEDING AND CURRENT ROW
    )
)
SELECT
    ts,
    dataset,
    host_name,
    user_name,
    printf('%d RC4 service tickets in 5 minutes: %s', services_5m,
           array_to_string(list_sort(services), ', ')) AS summary,
    ids AS event_ids
FROM bursts
-- One alert per burst: the moment the count first reaches 3.
QUALIFY services_5m >= 3
    AND coalesce(lag(services_5m) OVER (PARTITION BY dataset, host_name, user_name ORDER BY ts),
                 0) < 3
