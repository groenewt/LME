-- This table is a sanitized adapter contract, not a native LiteLLM schema guess.
CREATE TABLE IF NOT EXISTS public.lme_litellm_status (
    service_id TEXT PRIMARY KEY CHECK (length(service_id) BETWEEN 1 AND 128),
    status SMALLINT NOT NULL CHECK (status BETWEEN 0 AND 3),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
    artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    observed_at TIMESTAMPTZ NOT NULL,
    last_success_at TIMESTAMPTZ,
    CHECK (last_success_at IS NULL OR last_success_at <= observed_at)
);
