-- R20: 10+ failed SSH logins ("Failed password" and similar) from one IP in 10 minutes.
WITH fails AS (
    SELECT
        event_id, ts, dataset, host_name, src_ip,
        count(*) OVER w                  AS fails_10m,
        count(DISTINCT user_name) OVER w AS users_10m,
        list(event_id) OVER w            AS fail_ids
    FROM events
    WHERE source = 'linux_auth' AND event_code = 'ssh_login_failure' AND src_ip IS NOT NULL
    WINDOW w AS (
        PARTITION BY dataset, host_name, src_ip ORDER BY ts
        RANGE BETWEEN INTERVAL 10 MINUTE PRECEDING AND CURRENT ROW
    )
)
SELECT
    ts,
    dataset,
    host_name,
    NULL AS user_name,
    printf('%d failed SSH logins from %s in 10 minutes (%d users)', fails_10m, src_ip, users_10m)
        AS summary,
    fail_ids AS event_ids
FROM fails
-- One alert per attack: the moment the count first reaches 10.
QUALIFY fails_10m >= 10
    AND coalesce(lag(fails_10m) OVER (PARTITION BY dataset, host_name, src_ip ORDER BY ts), 0)
        < 10
