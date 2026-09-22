-- Run against the authoritative PostgreSQL database AFTER --schema-only and BEFORE publications.
-- Read-only checks: fail non-vacuously on missing fields, incompatible types, or primary keys.
DO $$
DECLARE actual text; expected record;
BEGIN
  FOR expected IN SELECT * FROM (VALUES
    ('hzb_monitor','id','bigint'), ('hzb_monitor','intervals','integer'),
    ('hzb_monitor','status','smallint'), ('hzb_monitor','type','smallint'),
    ('hzb_monitor','gmt_create','timestamp'), ('hzb_monitor','gmt_update','timestamp'),
    ('hzb_collector','id','bigint'), ('hzb_collector','status','smallint'),
    ('hzb_collector','gmt_create','timestamp'), ('hzb_collector','gmt_update','timestamp')
  ) AS fields(table_name,column_name,expected_type)
  LOOP
    SELECT data_type INTO actual FROM information_schema.columns
      WHERE table_schema='public' AND table_name=expected.table_name AND column_name=expected.column_name;
    IF actual IS NULL OR (expected.expected_type='timestamp' AND actual!='timestamp without time zone')
      OR (expected.expected_type!='timestamp' AND actual!=expected.expected_type) THEN
      RAISE EXCEPTION 'Native HB column %.% requires %, found %',
        expected.table_name,expected.column_name,expected.expected_type,coalesce(actual,'MISSING');
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
      JOIN pg_namespace n ON n.oid=t.relnamespace
      JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=c.conkey[1]
      WHERE n.nspname='public' AND t.relname IN ('hzb_monitor','hzb_collector')
      AND c.contype='p' AND cardinality(c.conkey)=1 AND a.attname='id') != 2 THEN
    RAISE EXCEPTION 'Native HB requires the id-only primary keys on both selected tables';
  END IF;
END $$;
