-- Local/CI stand-in for the parts of Supabase the migrations rely on.
-- NOT applied to a real Supabase project (those objects already exist there).
-- It reproduces Supabase's default behaviour that matters for security:
--   * anon / authenticated get ALL on new public tables (so RLS is the only guard)
--   * service_role bypasses RLS
--   * new functions are executable by PUBLIC unless revoked

create extension if not exists pgcrypto;

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;

grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;

create schema if not exists auth;
create table if not exists auth.users (id uuid primary key, email text, phone text);
create or replace function auth.uid() returns uuid language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated, service_role;

-- realtime.send() stand-in: records broadcasts so tests can assert on them.
create schema if not exists realtime;
create table if not exists realtime.sent (id bigserial primary key, topic text, event text, payload jsonb, private boolean, at timestamptz default now());
create or replace function realtime.send(payload jsonb, event text, topic text, private boolean default true)
returns void language sql as $$
  insert into realtime.sent (topic, event, payload, private) values (topic, event, payload, private)
$$;
grant usage on schema realtime to anon, authenticated, service_role;
