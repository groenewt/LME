-- Compare against the complete required list: zero rows is NOT a pass.
SELECT slot_name, synced, temporary, failover, invalidation_reason
FROM pg_replication_slots WHERE slot_type = 'logical';
