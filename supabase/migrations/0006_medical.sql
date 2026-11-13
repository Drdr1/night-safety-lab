-- Medical information (GDPR Art. 9 special-category data).
--
--  * Encrypted at field level by the server (AES-256-GCM, server/medical-crypto.ts).
--    The key never enters Postgres, so a DB dump, backup or SQL-editor session
--    sees ciphertext only.
--  * Separate, explicit consent, timestamped; withdrawing consent deletes the data.
--  * No RLS policy grants SELECT on medical_records to anyone. The only read
--    paths are the two functions below.
--  * Team can read it only while an alert for that member is open, and every
--    read is written to an append-only log in the same transaction.

create table public.medical_records (
  member_id    uuid primary key references public.members (id) on delete cascade,
  ciphertext   text not null,                    -- 'v<keyVersion>.<iv>.<tag>.<data>' base64url
  key_version  smallint not null,
  consent_at   timestamptz not null,
  updated_at   timestamptz not null default now()
);

create table public.medical_access_log (
  id         bigint generated always as identity primary key,
  member_id  uuid not null references public.members (id) on delete cascade,
  viewer     uuid not null,
  alert_id   uuid not null,
  purpose    text not null,
  viewed_at  timestamptz not null default now()
);

-- Append-only: no edits, no deletes (except the member-deletion cascade).
create or replace function public.forbid_log_change() returns trigger
language plpgsql as $$
begin
  if tg_op = 'UPDATE' then raise exception 'medical_access_log is append-only'; end if;
  if tg_op = 'DELETE' and exists (select 1 from public.members where id = old.member_id) then
    raise exception 'medical_access_log is append-only';
  end if;
  return old;
end $$;
create trigger medical_access_log_append_only
  before update or delete on public.medical_access_log
  for each row execute function public.forbid_log_change();

create or replace function public.save_my_medical(p_ciphertext text, p_key_version smallint, p_consent boolean) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_member uuid := public.current_member_id();
begin
  if v_member is null or not public.member_has_access() then raise exception 'no active membership'; end if;
  if p_consent is not true then raise exception 'explicit consent is required to store medical information'; end if;
  if p_ciphertext !~ '^v[0-9]+\.' then raise exception 'medical data must be encrypted before storage'; end if;
  insert into public.medical_records (member_id, ciphertext, key_version, consent_at)
  values (v_member, p_ciphertext, p_key_version, now())
  on conflict (member_id) do update
    set ciphertext = excluded.ciphertext, key_version = excluded.key_version, updated_at = now();
end $$;

create or replace function public.withdraw_medical_consent() returns void
language sql security definer set search_path = public, pg_temp as $$
  delete from public.medical_records where member_id = public.current_member_id()
$$;

create or replace function public.my_medical_ciphertext() returns text
language sql stable security definer set search_path = public, pg_temp as $$
  select ciphertext from public.medical_records where member_id = public.current_member_id()
$$;

-- Break-glass read for the team.
create or replace function public.authorize_medical_view(p_alert uuid, p_purpose text) returns text
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_member uuid; v_ct text;
begin
  if not public.is_team() then raise exception 'team only'; end if;
  if coalesce(btrim(p_purpose), '') = '' then raise exception 'a purpose is required'; end if;

  select member_id into v_member from public.alerts where id = p_alert and status <> 'resolved';
  if v_member is null then raise exception 'medical information is only available during an active alert'; end if;

  select ciphertext into v_ct from public.medical_records where member_id = v_member;
  if v_ct is null then return null; end if;

  insert into public.medical_access_log (member_id, viewer, alert_id, purpose)
  values (v_member, auth.uid(), p_alert, p_purpose);
  perform public.log_incident(p_alert, auth.uid()::text, 'Medical information viewed: ' || p_purpose);
  return v_ct;
end $$;

revoke execute on function public.save_my_medical(text, smallint, boolean), public.withdraw_medical_consent(),
                            public.my_medical_ciphertext(), public.authorize_medical_view(uuid, text) from public, anon;
grant execute on function public.save_my_medical(text, smallint, boolean), public.withdraw_medical_consent(),
                          public.my_medical_ciphertext(), public.authorize_medical_view(uuid, text) to authenticated;
