-- Workplace spreadsheet-export tables.
-- Run this once in the Supabase SQL editor (Project → SQL Editor → New query).
-- Mirrors the shape of the existing school-climate tables (sessions /
-- rated_responses / dream_big_responses) but kept isolated so Workplace rows
-- never collide with School Climate's own 'staff' role in the same bucket.
--
-- If your existing school-climate tables have Row Level Security (RLS)
-- policies restricting access to the service role, apply the same policies
-- here so the backend (which writes via the service-role key) keeps working
-- and nothing else can read/write these tables.

create table if not exists workplace_sessions (
  id                        text primary key,
  deployment_id             text not null,
  organization_id           text not null,
  role                      text not null default 'staff',
  response_mode             text not null default 'voice',
  token                     text,
  status                    text not null default 'completed',
  rated_question_count      integer not null default 0,
  dream_big_question_count  integer not null default 0,
  started_at                timestamptz,
  completed_at              timestamptz not null default now(),
  is_test                   boolean not null default false,
  created_at                timestamptz not null default now()
);

create table if not exists workplace_rated_responses (
  session_id     text not null,
  deployment_id  text not null,
  question_id    text not null,
  role           text not null default 'staff',
  domain         text not null,
  rating         integer not null check (rating between 1 and 4),
  followup_text  text,
  response_mode  text not null default 'voice',
  created_at     timestamptz not null default now(),
  primary key (session_id, question_id)
);

create table if not exists workplace_dream_big_responses (
  session_id     text not null,
  deployment_id  text not null,
  question_id    text not null,
  role           text not null default 'staff',
  prompt_text    text,
  response_text  text,
  followup_text  text,
  word_count     integer default 0,
  response_mode  text not null default 'voice',
  created_at     timestamptz not null default now(),
  primary key (session_id, question_id)
);

-- Helpful indexes for the spreadsheet/BI side of things.
create index if not exists workplace_sessions_org_idx        on workplace_sessions (organization_id);
create index if not exists workplace_rated_responses_org_idx on workplace_rated_responses (deployment_id);
create index if not exists workplace_dream_big_org_idx       on workplace_dream_big_responses (deployment_id);
