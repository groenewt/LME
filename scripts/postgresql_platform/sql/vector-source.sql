CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS public.docs_chunks (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    title TEXT,
    section TEXT,
    chunk_index INTEGER,
    content TEXT NOT NULL,
    embedding vector(768),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS docs_chunks_embedding_idx
    ON public.docs_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10);

-- Synthetic fixtures only; production corpus rows are never copied into this table.
CREATE TABLE IF NOT EXISTS public.lme_vector_probe (
    probe_id UUID PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    fixture_version INTEGER NOT NULL CHECK (fixture_version > 0),
    embedding vector(768) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
