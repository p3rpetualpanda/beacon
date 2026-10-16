-- Normalise one staged Zeek JSON log (table raw_stage, column j JSON) into events.
-- Parameters: $dataset (manifest name).
-- OTRF ships every Zeek log type in one file; "@stream" names the type (conn, dns, http, ...).
-- Zeek's ts is epoch seconds in UTC, so no offset is needed.

CREATE OR REPLACE TEMP TABLE stage_typed AS
SELECT
    j,
    -- Zeek's own housekeeping logs describe the sensor, not the network, so they are rejected.
    CASE WHEN j ->> '@stream' IN ('loaded_scripts', 'stats', 'capture_loss', 'packet_filter',
                                  'reporter')
         THEN NULL
         ELSE nullif(j ->> '@stream', '')
    END                                                            AS stream,
    make_timestamp(try_cast(try_cast(j ->> 'ts' AS DOUBLE) * 1000000 AS BIGINT)) AS ts
FROM raw_stage;

INSERT OR IGNORE INTO events (
    event_id, ts, ts_source, dataset, source, channel, event_code, event_category,
    event_action, event_outcome, src_ip, src_port, dst_ip, dst_port, network_protocol,
    dns_query, raw
)
SELECT
    md5(j::VARCHAR)                                                AS event_id,
    stage_typed.ts,
    'utc_field'                                                    AS ts_source,
    $dataset                                                       AS dataset,
    'zeek'                                                         AS source,
    stream                                                         AS channel,
    stream                                                         AS event_code,
    m.category                                                     AS event_category,
    m.action                                                       AS event_action,
    m.outcome                                                      AS event_outcome,
    j ->> 'id_orig_h'                                              AS src_ip,
    try_cast(j ->> 'id_orig_p' AS INTEGER)                         AS src_port,
    j ->> 'id_resp_h'                                              AS dst_ip,
    try_cast(j ->> 'id_resp_p' AS INTEGER)                         AS dst_port,
    lower(j ->> 'proto')                                           AS network_protocol,
    CASE WHEN stream = 'dns' THEN lower(j ->> 'query') END         AS dns_query,
    j                                                              AS raw
FROM stage_typed
LEFT JOIN event_code_map m
       ON m.source = 'zeek'
      AND m.event_code = stage_typed.stream
WHERE stage_typed.ts IS NOT NULL
  AND stream IS NOT NULL
-- Within one file, keep a single copy of any identical record.
QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY stage_typed.ts) = 1;
