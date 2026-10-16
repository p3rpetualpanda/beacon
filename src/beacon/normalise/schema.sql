-- Beacon's core tables. Field names follow the Elastic Common Schema (ECS) where one exists.

CREATE TABLE IF NOT EXISTS events (
    event_id              VARCHAR PRIMARY KEY,  -- stable hash, so reloading never duplicates
    ts                    TIMESTAMP NOT NULL,   -- always UTC
    ts_source             VARCHAR NOT NULL,     -- how ts was derived: utc_field | local_plus_offset | syslog
    dataset               VARCHAR NOT NULL,     -- manifest dataset name
    source                VARCHAR NOT NULL,     -- sysmon | winsec | powershell | system | windows_other | linux_auth
    channel               VARCHAR,              -- Windows event log channel
    event_code            VARCHAR NOT NULL,     -- Windows event ID, or a parser-defined code
    event_category        VARCHAR,              -- ECS category: authentication, process, network, ...
    event_action          VARCHAR,              -- short description of what happened
    event_outcome         VARCHAR,              -- success | failure
    host_name             VARCHAR,              -- short, lower-case host name
    host_fqdn             VARCHAR,
    user_name             VARCHAR,              -- lower-case, domain stripped
    user_domain           VARCHAR,
    logon_type            INTEGER,
    process_id            BIGINT,
    process_path          VARCHAR,
    process_name          VARCHAR,              -- lower-case file name of process_path
    process_command_line  VARCHAR,
    parent_process_path   VARCHAR,
    parent_process_name   VARCHAR,
    target_process_path   VARCHAR,              -- Sysmon 10: the process being accessed
    target_process_name   VARCHAR,
    granted_access        VARCHAR,
    registry_path         VARCHAR,
    registry_value        VARCHAR,
    service_name          VARCHAR,
    service_path          VARCHAR,
    task_name             VARCHAR,
    src_ip                VARCHAR,
    src_port              INTEGER,
    dst_ip                VARCHAR,
    dst_port              INTEGER,
    network_protocol      VARCHAR,
    dns_query             VARCHAR,
    raw                   JSON                  -- the original record, kept for investigation
);

CREATE TABLE IF NOT EXISTS datasets (
    name               VARCHAR PRIMARY KEY,
    description        VARCHAR,
    source             VARCHAR,
    licence            VARCHAR,
    format             VARCHAR,
    attack_techniques  VARCHAR[]   -- ATT&CK techniques the dataset is documented to contain
);

CREATE TABLE IF NOT EXISTS data_quality (
    loaded_at           TIMESTAMP NOT NULL,
    dataset             VARCHAR NOT NULL,
    rows_read           BIGINT NOT NULL,
    rows_rejected       BIGINT NOT NULL,  -- no usable timestamp
    duplicates_dropped  BIGINT NOT NULL,
    rows_loaded         BIGINT NOT NULL,
    min_ts              TIMESTAMP,
    max_ts              TIMESTAMP,
    pct_null_host       DOUBLE,
    pct_null_user       DOUBLE,
    ts_offset_hours     DOUBLE            -- local-to-UTC offset inferred for this dataset, if any
);

-- Maps each source's event codes to ECS category/action/outcome. Reloaded from event_codes.csv.
CREATE TABLE IF NOT EXISTS event_code_map (
    source      VARCHAR NOT NULL,
    event_code  VARCHAR NOT NULL,
    category    VARCHAR NOT NULL,
    action      VARCHAR NOT NULL,
    outcome     VARCHAR,
    PRIMARY KEY (source, event_code)
);

-- Detection rules, loaded from detections/*/rule.yml by `beacon detect`.
CREATE TABLE IF NOT EXISTS rules (
    rule_id      VARCHAR PRIMARY KEY,  -- R01, R02, ...
    name         VARCHAR NOT NULL,
    technique    VARCHAR NOT NULL,     -- ATT&CK technique, e.g. T1003.001
    tactic       VARCHAR NOT NULL,
    severity     VARCHAR NOT NULL,     -- low | medium | high | critical
    description  VARCHAR
);

-- One row per rule hit. Re-running a rule keeps existing alerts (and their status).
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    VARCHAR PRIMARY KEY,   -- hash of the rule and its evidence, so re-runs match
    rule_id     VARCHAR NOT NULL,
    ts          TIMESTAMP NOT NULL,    -- when the behaviour completed
    dataset     VARCHAR,
    host_name   VARCHAR,
    user_name   VARCHAR,
    summary     VARCHAR NOT NULL,
    event_ids   VARCHAR[] NOT NULL,    -- evidence in events
    status      VARCHAR NOT NULL DEFAULT 'new',  -- new | triaged | true_positive | false_positive | closed
    created_at  TIMESTAMP NOT NULL DEFAULT current_timestamp
);

-- Hits and precision per rule. With no per-event attack labels, a hit counts as a true positive
-- when its dataset is documented to contain the rule's technique, its parent or a sub-technique.
CREATE OR REPLACE VIEW rule_performance AS
SELECT
    r.rule_id,
    r.name,
    r.technique,
    r.severity,
    count(a.alert_id)                          AS hits,
    count(a.alert_id) FILTER (WHERE a.matched) AS true_positives,
    true_positives / nullif(hits, 0)           AS precision
FROM rules r
LEFT JOIN (
    SELECT
        a.alert_id,
        a.rule_id,
        len(list_filter(
            coalesce(d.attack_techniques, []),
            t -> t = r.technique OR starts_with(t, r.technique || '.')
                 OR starts_with(r.technique, t || '.')
        )) > 0 AS matched
    FROM alerts a
    JOIN rules r USING (rule_id)
    LEFT JOIN datasets d ON d.name = a.dataset
) a USING (rule_id)
GROUP BY ALL
ORDER BY r.rule_id;
