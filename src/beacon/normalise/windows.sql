-- Normalise one staged OTRF Windows dataset (table raw_stage, column j JSON) into events.
-- Parameters: $dataset (manifest name), $offset_s (seconds to add to local timestamps, or NULL).

-- The APT29 export decoded some UTF-8 as Windows-1252, so the right-to-left override (U+202E)
-- used to disguise file extensions reads as "â€®". Repair it so detections can match U+202E.
CREATE OR REPLACE TEMP MACRO fix_text(v) AS replace(v, 'â€®', chr(8238));

CREATE OR REPLACE TEMP MACRO fld(j, k) AS
    fix_text(nullif(nullif(trim(json_extract_string(j, '$."' || k || '"')), '-'), ''));

-- File name of a Windows or Unix path, lower-cased.
CREATE OR REPLACE TEMP MACRO basename(p) AS lower(regexp_extract(p, '[^\\/]+$'));

-- Integer that may be written as decimal or hex (Security events use 0x1158 style).
CREATE OR REPLACE TEMP MACRO to_int(v) AS try_cast(v AS BIGINT);

-- A few Sysmon records reached NXLog unparsed, with every field only inside the rendered
-- "Message" text ("Image: C:\...\powershell.exe" lines). Recover those fields from it;
-- fields NXLog did parse take precedence, and the record is flagged BeaconFieldsFromMessage.
UPDATE raw_stage
SET j = json_merge_patch(
    list_reduce(
        list_transform(
            list_filter(
                string_split(replace(json_extract_string(j, '$.Message'), chr(13), ''), chr(10)),
                line -> regexp_matches(line, '^[A-Za-z]+: ')
            ),
            line -> json_object(split_part(line, ': ', 1), substr(line, strpos(line, ': ') + 2))
        ),
        (a, b) -> json_merge_patch(a, b)
    ),
    j,
    json_object('BeaconFieldsFromMessage', true)
)
WHERE lower(json_extract_string(j, '$.Channel')) = 'microsoft-windows-sysmon/operational'
  AND json_extract_string(j, '$.UtcTime') IS NULL
  AND regexp_matches(json_extract_string(j, '$.Message'), '\nUtcTime: ');

CREATE OR REPLACE TEMP TABLE stage_typed AS
SELECT
    j,
    lower(fld(j, 'Channel'))                                       AS channel_lc,
    fld(j, 'Channel')                                              AS channel,
    CASE lower(fld(j, 'Channel'))
        WHEN 'microsoft-windows-sysmon/operational' THEN 'sysmon'
        WHEN 'security' THEN 'winsec'
        WHEN 'windows powershell' THEN 'powershell'
        WHEN 'microsoft-windows-powershell/operational' THEN 'powershell'
        WHEN 'system' THEN 'system'
        ELSE 'windows_other'
    END                                                            AS source,
    fld(j, 'EventID')                                              AS event_code,
    try_strptime(fld(j, 'UtcTime'), '%Y-%m-%d %H:%M:%S.%g')       AS utc_ts,
    try_strptime(coalesce(fld(j, 'EventTime'), fld(j, 'TimeCreated')),
                 ['%Y-%m-%d %H:%M:%S.%g', '%Y-%m-%d %H:%M:%S'])    AS local_ts,
    -- Sysmon logs the real user in "User"; AccountName on Sysmon rows is the Sysmon service (SYSTEM).
    coalesce(
        fld(j, 'TargetUserName'),
        fld(j, 'User'),
        fld(j, 'SubjectUserName'),
        CASE WHEN lower(fld(j, 'Channel')) <> 'microsoft-windows-sysmon/operational'
             THEN fld(j, 'AccountName') END
    )                                                              AS user_raw,
    coalesce(fld(j, 'TargetDomainName'), fld(j, 'SubjectDomainName'),
             CASE WHEN lower(fld(j, 'Channel')) <> 'microsoft-windows-sysmon/operational'
                  THEN fld(j, 'Domain') END)                       AS domain_raw
FROM raw_stage;

INSERT OR IGNORE INTO events
SELECT
    coalesce(
        md5(lower(fld(j, 'Hostname')) || '|' || channel_lc || '|' || fld(j, 'RecordNumber')),
        md5(j::VARCHAR)
    )                                                              AS event_id,
    coalesce(utc_ts, local_ts + to_seconds($offset_s))             AS ts,
    CASE WHEN utc_ts IS NOT NULL THEN 'utc_field' ELSE 'local_plus_offset' END AS ts_source,
    $dataset                                                       AS dataset,
    stage_typed.source,
    channel,
    stage_typed.event_code,
    m.category                                                     AS event_category,
    m.action                                                       AS event_action,
    m.outcome                                                      AS event_outcome,
    lower(split_part(fld(j, 'Hostname'), '.', 1))                  AS host_name,
    lower(fld(j, 'Hostname'))                                      AS host_fqdn,
    lower(regexp_extract(user_raw, '[^\\]+$'))                     AS user_name,
    coalesce(
        CASE WHEN contains(user_raw, '\') THEN upper(split_part(user_raw, '\', 1)) END,
        upper(domain_raw)
    )                                                              AS user_domain,
    to_int(fld(j, 'LogonType'))                                    AS logon_type,
    to_int(coalesce(fld(j, 'NewProcessId'), fld(j, 'ProcessId'), fld(j, 'SourceProcessId'))) AS process_id,
    coalesce(fld(j, 'Image'), fld(j, 'NewProcessName'), fld(j, 'SourceImage'),
             fld(j, 'Application'), fld(j, 'ProcessName'))         AS process_path,
    basename(coalesce(fld(j, 'Image'), fld(j, 'NewProcessName'), fld(j, 'SourceImage'),
                      fld(j, 'Application'), fld(j, 'ProcessName'))) AS process_name,
    fld(j, 'CommandLine')                                          AS process_command_line,
    coalesce(fld(j, 'ParentImage'), fld(j, 'ParentProcessName'))   AS parent_process_path,
    basename(coalesce(fld(j, 'ParentImage'), fld(j, 'ParentProcessName'))) AS parent_process_name,
    fld(j, 'TargetImage')                                          AS target_process_path,
    basename(fld(j, 'TargetImage'))                                AS target_process_name,
    fld(j, 'GrantedAccess')                                        AS granted_access,
    fld(j, 'TargetObject')                                         AS registry_path,
    CASE WHEN stage_typed.source = 'sysmon' THEN fld(j, 'Details') END         AS registry_value,
    fld(j, 'ServiceName')                                          AS service_name,
    coalesce(fld(j, 'ImagePath'), fld(j, 'ServiceFileName'))       AS service_path,
    fld(j, 'TaskName')                                             AS task_name,
    coalesce(fld(j, 'IpAddress'), fld(j, 'SourceIp'), fld(j, 'SourceAddress')) AS src_ip,
    to_int(coalesce(fld(j, 'IpPort'), fld(j, 'SourcePort')))       AS src_port,
    coalesce(fld(j, 'DestinationIp'), fld(j, 'DestAddress'))       AS dst_ip,
    to_int(coalesce(fld(j, 'DestinationPort'), fld(j, 'DestPort'))) AS dst_port,
    lower(CASE fld(j, 'Protocol') WHEN '6' THEN 'tcp' WHEN '17' THEN 'udp' ELSE fld(j, 'Protocol') END)
                                                                   AS network_protocol,
    lower(fld(j, 'QueryName'))                                     AS dns_query,
    j                                                              AS raw
FROM stage_typed
LEFT JOIN event_code_map m
       ON m.source = stage_typed.source
      AND m.event_code = stage_typed.event_code
WHERE coalesce(utc_ts, local_ts + to_seconds($offset_s)) IS NOT NULL
  AND stage_typed.event_code IS NOT NULL
-- Within one file, keep a single copy of any record collected more than once.
QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY ts) = 1;
