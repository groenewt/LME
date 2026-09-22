-- Run on EACH subscriber database. Include completed table-sync slots (state f).
SELECT s.subslotname AS slot_name
FROM pg_subscription s WHERE s.subfailover AND s.subslotname IS NOT NULL
UNION
SELECT CONCAT('pg_', r.srsubid, '_sync_', r.srrelid, '_', ctl.system_identifier)
FROM pg_control_system() ctl, pg_subscription_rel r, pg_subscription s
WHERE r.srsubstate = 'f' AND s.oid = r.srsubid AND s.subfailover;
