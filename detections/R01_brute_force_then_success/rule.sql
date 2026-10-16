-- R01: 10+ failed logons (4625) for one user from one IP in 10 minutes, then a successful
-- logon (4624) for that user from that IP within 10 minutes of a failure in the burst.
WITH fails AS (
    SELECT
        event_id, ts, dataset, user_name, src_ip,
        count(*) OVER w       AS fails_10m,
        list(event_id) OVER w AS fail_ids
    FROM events
    WHERE source = 'winsec' AND event_code = '4625'
      AND user_name IS NOT NULL AND src_ip IS NOT NULL
    WINDOW w AS (
        PARTITION BY dataset, user_name, src_ip ORDER BY ts
        RANGE BETWEEN INTERVAL 10 MINUTE PRECEDING AND CURRENT ROW
    )
)
SELECT
    s.ts,
    s.dataset,
    s.host_name,
    s.user_name,
    printf('%d failed logons for %s from %s, then a successful logon',
           f.fails_10m, s.user_name, s.src_ip) AS summary,
    list_append(f.fail_ids, s.event_id) AS event_ids
FROM events s
JOIN fails f
  ON f.dataset = s.dataset AND f.user_name = s.user_name AND f.src_ip = s.src_ip
 AND s.ts BETWEEN f.ts AND f.ts + INTERVAL 10 MINUTE
WHERE s.source = 'winsec' AND s.event_code = '4624' AND f.fails_10m >= 10
-- One alert per successful logon, using the latest burst before it.
QUALIFY row_number() OVER (PARTITION BY s.event_id ORDER BY f.ts DESC) = 1
