-- R02: one IP fails to log on (4625) as 15+ different users in 10 minutes.
WITH fails AS (
    SELECT
        event_id, ts, dataset, host_name, src_ip,
        count(DISTINCT user_name) OVER w AS users_10m,
        list(event_id) OVER w            AS fail_ids
    FROM events
    WHERE source = 'winsec' AND event_code = '4625'
      AND user_name IS NOT NULL AND src_ip IS NOT NULL
    WINDOW w AS (
        PARTITION BY dataset, src_ip ORDER BY ts
        RANGE BETWEEN INTERVAL 10 MINUTE PRECEDING AND CURRENT ROW
    )
)
SELECT
    ts,
    dataset,
    host_name,
    NULL AS user_name,
    printf('%s failed to log on as %d different users in 10 minutes', src_ip, users_10m)
        AS summary,
    fail_ids AS event_ids
FROM fails
-- One alert per spray: the moment the count first reaches 15.
QUALIFY users_10m >= 15
    AND coalesce(lag(users_10m) OVER (PARTITION BY dataset, src_ip ORDER BY ts), 0) < 15
