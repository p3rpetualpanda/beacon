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
