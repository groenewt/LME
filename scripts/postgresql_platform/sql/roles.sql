-- Execute once per fresh cluster. Passwords are supplied separately through the
-- repaired credential provider; these roles cannot log in until provisioned.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lme_schema') THEN
    CREATE ROLE lme_schema NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lme_replica_reader') THEN
    CREATE ROLE lme_replica_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lme_replicator') THEN
    CREATE ROLE lme_replicator LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
ALTER ROLE lme_replica_reader SET default_transaction_read_only = on;
ALTER ROLE lme_replicator SET synchronous_commit = on;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
