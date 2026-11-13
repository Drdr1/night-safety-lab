-- Alerts, incident log and the outbound message queue.
-- Nothing sends WhatsApp/SMS from inside Postgres: functions enqueue rows in
-- `outbox`, and server/outbox-worker.ts delivers them (WhatsApp template first,
-- SMS fallback), so a provider outage never blocks or rolls back an alert.

create table public.alerts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.members (id) on delete cascade,
  kind         text not null check (kind in ('home_by_missed', 'call_me', 'send_team_member', 'go_112')),
  status       text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
  escalation_step smallint not null default 1,   -- 1 = member messaged, 2 = contact messaged
  source_timer_id uuid,
  opened_at    timestamptz not null default now(),
  resolved_at  timestamptz
);
create index alerts_open_idx on public.alerts (status, opened_at) where status <> 'resolved';

create table public.incident_log (
  id        bigint generated always as identity primary key,
  alert_id  uuid not null references public.alerts (id) on delete cascade,
  actor     text not null,                       -- 'system', 'member', or a staff user id
  note      text not null,
  at        timestamptz not null default now()
);

create table public.outbox (
  id          bigint generated always as identity primary key,
  template    text not null,                     -- pre-approved WhatsApp template name
  to_phone    text,                              -- null = team ops channel
  params      jsonb not null default '{}',
  member_id   uuid references public.members (id) on delete cascade,
  alert_id    uuid references public.alerts (id) on delete cascade,
  status      text not null default 'pending' check (status in ('pending', 'sending', 'sent', 'failed')),
  channel     text,                              -- 'whatsapp' | 'sms' once delivered
  attempts    smallint not null default 0,
  last_error  text,
  created_at  timestamptz not null default now(),
  sent_at     timestamptz
);
create index outbox_pending_idx on public.outbox (created_at) where status = 'pending';

create or replace function public.log_incident(p_alert uuid, p_actor text, p_note text) returns void
language sql security definer set search_path = public, pg_temp as $$
  insert into public.incident_log (alert_id, actor, note) values (p_alert, p_actor, p_note)
$$;
revoke execute on function public.log_incident(uuid, text, text) from public, anon, authenticated;

-- Help menu: one call, one alert, team notified at once.
create or replace function public.raise_help(p_kind text) returns uuid
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_member uuid := public.current_member_id(); v_alert uuid; v_name text;
begin
  if v_member is null or not public.member_has_access() then raise exception 'no active membership'; end if;
  if p_kind not in ('call_me', 'send_team_member', 'go_112') then raise exception 'unknown help option'; end if;

  insert into public.alerts (member_id, kind) values (v_member, p_kind) returning id into v_alert;
  select full_name into v_name from public.members where id = v_member;
  perform public.log_incident(v_alert, 'member', 'Member pressed help: ' || p_kind);
  insert into public.outbox (template, to_phone, params, member_id, alert_id)
  values ('team_help_request', null, jsonb_build_object('member', v_name, 'kind', p_kind), v_member, v_alert);
  return v_alert;
end $$;
revoke execute on function public.raise_help(text) from public, anon;
grant execute on function public.raise_help(text) to authenticated;

-- Team actions on an alert, always logged.
create or replace function public.update_alert(p_alert uuid, p_status text, p_note text) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not public.is_team() then raise exception 'team only'; end if;
  if p_status not in ('acknowledged', 'resolved') then raise exception 'bad status'; end if;
  update public.alerts set status = p_status,
         resolved_at = case when p_status = 'resolved' then now() end
   where id = p_alert;
  if not found then raise exception 'alert not found'; end if;
  perform public.log_incident(p_alert, auth.uid()::text, coalesce(p_note, 'Status set to ' || p_status));
end $$;
revoke execute on function public.update_alert(uuid, text, text) from public, anon;
grant execute on function public.update_alert(uuid, text, text) to authenticated;
