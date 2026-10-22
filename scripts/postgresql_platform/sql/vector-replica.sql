CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS public.docs_chunks (
    id INTEGER PRIMARY KEY,
    chunk_index INTEGER,
    created_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS public.lme_vector_probe (
    probe_id UUID PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    fixture_version INTEGER NOT NULL CHECK (fixture_version > 0),
    embedding vector(768) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
