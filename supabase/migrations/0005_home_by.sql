-- Home By. The timer lives in the database and is swept by pg_cron every
-- minute, so a dead or offline phone still triggers the alert.
-- Escalation: step 1 alert the team + message the member,
--             step 2 (no reply after a grace period) message the chosen contact.

create table public.home_by_timers (
  id          uuid primary key default gen_random_uuid(),
  member_id   uuid not null references public.members (id) on delete cascade,
  due_at      timestamptz not null,
  contact_id  uuid references public.emergency_contacts (id) on delete set null,
  status      text not null default 'armed' check (status in ('armed', 'home', 'missed', 'cancelled')),
  created_at  timestamptz not null default now()
);
-- One live timer per member.
create unique index home_by_one_armed on public.home_by_timers (member_id) where status = 'armed';
create index home_by_due_idx on public.home_by_timers (due_at) where status = 'armed';

create table public.settings (
  key   text primary key,
  value text not null
);
insert into public.settings values ('home_by_contact_grace_minutes', '10');

create or replace function public.set_home_by(p_due_at timestamptz, p_contact uuid) returns uuid
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_member uuid := public.current_member_id(); v_id uuid;
begin
  if not public.member_has_access() then raise exception 'no active membership'; end if;
  if p_due_at <= now() + interval '5 minutes' or p_due_at > now() + interval '24 hours' then
    raise exception 'arrival time must be between 5 minutes and 24 hours from now';
  end if;
  if p_contact is not null and not exists
     (select 1 from public.emergency_contacts where id = p_contact and member_id = v_member) then
    raise exception 'contact not found';
  end if;
  update public.home_by_timers set status = 'cancelled' where member_id = v_member and status = 'armed';
  insert into public.home_by_timers (member_id, due_at, contact_id)
  values (v_member, p_due_at, p_contact) returning id into v_id;
  return v_id;
end $$;
revoke execute on function public.set_home_by(timestamptz, uuid) from public, anon;
grant execute on function public.set_home_by(timestamptz, uuid) to authenticated;

-- "I'm home": disarms the timer, or closes the alert if it already fired.
create or replace function public.mark_home() returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_member uuid := public.current_member_id(); v_alert uuid;
begin
  if v_member is null then raise exception 'not a member'; end if;
  update public.home_by_timers set status = 'home'
   where member_id = v_member and status in ('armed', 'missed');
  for v_alert in
    update public.alerts set status = 'resolved', resolved_at = now()
     where member_id = v_member and kind = 'home_by_missed' and status <> 'resolved'
    returning id
  loop
    perform public.log_incident(v_alert, 'member', 'Member tapped Home');
    insert into public.outbox (template, to_phone, params, member_id, alert_id)
    values ('team_member_home', null, jsonb_build_object('alert', v_alert), v_member, v_alert);
  end loop;
end $$;
revoke execute on function public.mark_home() from public, anon;
grant execute on function public.mark_home() to authenticated;

-- Step 1: overdue timers -> alert + team + member check-in.
create or replace function public.fire_overdue_home_by() returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare t record; v_alert uuid; n integer := 0;
begin
  for t in
    select h.*, m.full_name, m.phone
      from public.home_by_timers h join public.members m on m.id = h.member_id
     where h.status = 'armed' and h.due_at <= now() and m.access_status = 'active'
     for update of h skip locked            -- safe if two sweeps overlap
  loop
    update public.home_by_timers set status = 'missed' where id = t.id;
    insert into public.alerts (member_id, kind, source_timer_id)
    values (t.member_id, 'home_by_missed', t.id) returning id into v_alert;
    perform public.log_incident(v_alert, 'system',
      format('Home By missed (due %s). Team alerted, member messaged.', to_char(t.due_at, 'HH24:MI')));
    insert into public.outbox (template, to_phone, params, member_id, alert_id) values
      ('team_home_by_missed', null, jsonb_build_object('member', t.full_name, 'due', t.due_at), t.member_id, v_alert),
      ('member_home_by_check', t.phone, jsonb_build_object('name', t.full_name), t.member_id, v_alert);
    n := n + 1;
  end loop;
  return n;
end $$;
revoke execute on function public.fire_overdue_home_by() from public, anon, authenticated;

-- Step 2: still unresolved after the grace period -> message the chosen contact.
create or replace function public.escalate_home_by_alerts() returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare a record; n integer := 0;
        v_grace interval := (select value from public.settings where key = 'home_by_contact_grace_minutes') || ' minutes';
begin
  for a in
    select al.id, al.member_id, m.full_name, c.name as contact_name, c.phone as contact_phone
      from public.alerts al
      join public.members m on m.id = al.member_id
      join public.home_by_timers h on h.id = al.source_timer_id
      left join public.emergency_contacts c on c.id = h.contact_id
     where al.kind = 'home_by_missed' and al.status = 'open'
       and al.escalation_step = 1 and al.opened_at <= now() - v_grace
     for update of al skip locked
  loop
    update public.alerts set escalation_step = 2 where id = a.id;
    if a.contact_phone is not null then
      insert into public.outbox (template, to_phone, params, member_id, alert_id)
      values ('contact_home_by_missed', a.contact_phone,
              jsonb_build_object('contact', a.contact_name, 'member', a.full_name), a.member_id, a.id);
      perform public.log_incident(a.id, 'system', 'No reply from member. Contact ' || a.contact_name || ' messaged.');
    else
      perform public.log_incident(a.id, 'system', 'No reply from member and no contact on the timer. Team to act.');
    end if;
    n := n + 1;
  end loop;
  return n;
end $$;
revoke execute on function public.escalate_home_by_alerts() from public, anon, authenticated;
grant execute on function public.fire_overdue_home_by(), public.escalate_home_by_alerts() to service_role;
