-- R16: one user runs 5+ different discovery commands on one host within 5 minutes
-- (Sysmon 1 or 4688). net.exe and net1.exe count by subcommand, so "net user" and
-- "net group" are different commands.
WITH discovery AS (
    SELECT
        event_id, ts, dataset, host_name, user_name,
        CASE
            WHEN process_name IN ('net.exe', 'net1.exe') THEN 'net ' || coalesce(
                regexp_extract(lower(process_command_line),
                               '\s(user|group|localgroup|accounts|view|share|session|use|config)\b',
                               1),
                '')
            ELSE replace(process_name, '.exe', '')
        END AS command
    FROM events
    WHERE ((source = 'sysmon' AND event_code = '1') OR (source = 'winsec' AND event_code = '4688'))
      AND process_name IN (
          'whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'systeminfo.exe', 'ipconfig.exe',
          'tasklist.exe', 'hostname.exe', 'quser.exe', 'qwinsta.exe', 'netstat.exe', 'arp.exe',
          'route.exe', 'dsquery.exe'
      )
      -- Tuned: the Azure VM agent runs ipconfig, arp and route itself for diagnostics. Only its
      -- real install folder is trusted, so a tool renamed to look like the agent still counts.
      AND NOT (
          coalesce(parent_process_name, '') IN ('windowsazureguestagent.exe', 'waappagent.exe')
          AND regexp_matches(coalesce(parent_process_path, ''), '(?i)^c:\\windowsazure\\')
      )
),
bursts AS (
    SELECT
        *,
        count(DISTINCT command) OVER w AS commands_5m,
        list(DISTINCT command) OVER w  AS commands,
        list(event_id) OVER w          AS ids
    FROM discovery
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
    printf('%d discovery commands in 5 minutes: %s', commands_5m,
           array_to_string(list_sort(commands), ', ')) AS summary,
    ids AS event_ids
FROM bursts
-- One alert per burst: the moment the count first reaches 5.
QUALIFY commands_5m >= 5
    AND coalesce(lag(commands_5m) OVER (PARTITION BY dataset, host_name, user_name ORDER BY ts),
                 0) < 5
