-- Run this once in your Supabase project's SQL Editor (Supabase dashboard -> SQL Editor -> New query)

create table if not exists kv_store (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);

-- Speeds up the "list keys by prefix" lookups used by the CRM (lead:, agent:, config:, crm:)
create index if not exists kv_store_key_prefix_idx on kv_store (key text_pattern_ops);
