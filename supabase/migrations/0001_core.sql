-- Core model: members, team staff, emergency profile and contacts.
-- A member row exists before its auth user (created by the Stripe webhook);
-- auth_user_id is linked when the single-use invite is redeemed.

create extension if not exists pgcrypto;

create table public.members (
  id              uuid primary key default gen_random_uuid(),
  auth_user_id    uuid unique,
  full_name       text not null check (length(full_name) between 1 and 120),
  email           text not null,
  phone           text,
  date_of_birth   date,
  access_status   text not null default 'pending'
                  check (access_status in ('pending', 'active', 'ended')),
  access_ended_reason text,
  created_at      timestamptz not null default now()
);
create unique index members_email_key on public.members (lower(email));

create table public.team_staff (
  user_id     uuid primary key,
  display_name text not null
);

create table public.emergency_profiles (
  member_id     uuid primary key references public.members (id) on delete cascade,
  photo_path    text,
  address       text,
  languages     text[] not null default '{}',
  safe_phrase   text,
  description   text,
  family_alert_enabled boolean not null default false,
  updated_at    timestamptz not null default now()
);

create table public.emergency_contacts (
  id          uuid primary key default gen_random_uuid(),
  member_id   uuid not null references public.members (id) on delete cascade,
  position    smallint not null check (position between 1 and 3),
  name        text not null,
  phone       text not null,
  relation    text,
  is_family   boolean not null default false,
  unique (member_id, position)              -- hard cap of 3 contacts
);

-- ---------- helpers used by RLS (security definer, fixed search_path) ----------

create or replace function public.current_member_id() returns uuid
language sql stable security definer set search_path = public, pg_temp as $$
  select id from public.members where auth_user_id = auth.uid()
$$;

create or replace function public.member_has_access() returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from public.members
                 where auth_user_id = auth.uid() and access_status = 'active')
$$;

create or replace function public.is_team() returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from public.team_staff where user_id = auth.uid())
$$;

revoke execute on function public.current_member_id(), public.member_has_access(), public.is_team() from public;
grant execute on function public.current_member_id(), public.member_has_access(), public.is_team() to authenticated;

-- Family alerts are an 18–25 option, and only the member can turn it on.
create or replace function public.check_family_alert() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare dob date;
begin
  if new.family_alert_enabled then
    select date_of_birth into dob from public.members where id = new.member_id;
    if dob is null or age(current_date, dob) >= interval '26 years' then
      raise exception 'family alert is only available to members aged 18-25';
    end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger emergency_profiles_family_alert
  before insert or update on public.emergency_profiles
  for each row execute function public.check_family_alert();
