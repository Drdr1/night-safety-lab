-- Night Roll Call. Friends join from a shared link with a name only (no
-- account, no phone number). Each friend gets a secret that lets them change
-- only their own status. Status changes are pushed live over a private
-- Supabase Realtime broadcast topic per roll call.

create table public.roll_calls (
  id           uuid primary key default gen_random_uuid(),
  owner_id     uuid not null references public.members (id) on delete cascade,
  title        text not null default 'Tonight' check (length(title) between 1 and 60),
  share_token  text not null unique default encode(gen_random_bytes(16), 'hex'),
  nudge_at     timestamptz not null,
  nudged_at    timestamptz,
  status       text not null default 'open' check (status in ('open', 'closed')),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null default now() + interval '18 hours'
);

create table public.roll_call_participants (
  id            uuid primary key default gen_random_uuid(),
  roll_call_id  uuid not null references public.roll_calls (id) on delete cascade,
  display_name  text not null check (length(btrim(display_name)) between 1 and 40),
  status        text not null default 'out' check (status in ('out', 'leaving', 'home')),
  secret_hash   text not null,
  nudged_at     timestamptz,
  updated_at    timestamptz not null default now()
);
create index on public.roll_call_participants (roll_call_id);

create or replace function public.create_roll_call(p_title text, p_nudge_at timestamptz) returns public.roll_calls
language plpgsql security definer set search_path = public, pg_temp as $$
declare v public.roll_calls;
begin
  if not public.member_has_access() then raise exception 'no active membership'; end if;
  if p_nudge_at <= now() or p_nudge_at > now() + interval '18 hours' then
    raise exception 'nudge time must be within the next 18 hours';
  end if;
  insert into public.roll_calls (owner_id, title, nudge_at)
  values (public.current_member_id(), coalesce(nullif(btrim(p_title), ''), 'Tonight'), p_nudge_at)
  returning * into v;
  return v;
end $$;
revoke execute on function public.create_roll_call(text, timestamptz) from public, anon;
grant execute on function public.create_roll_call(text, timestamptz) to authenticated;

-- Live updates: one broadcast per change, on topic roll_call:<id>.
create or replace function public.broadcast_roll_call_change() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if to_regprocedure('realtime.send(jsonb,text,text,boolean)') is not null then
    perform realtime.send(
      jsonb_build_object('participant_id', new.id, 'name', new.display_name,
                         'status', new.status, 'nudged', new.nudged_at is not null),
      'status', 'roll_call:' || new.roll_call_id, true);
  end if;
  return new;
end $$;
create trigger roll_call_participants_broadcast
  after insert or update of status, nudged_at on public.roll_call_participants
  for each row execute function public.broadcast_roll_call_change();

create or replace function public.join_roll_call(p_share_token text, p_name text)
returns table (participant_id uuid, secret text, roll_call_id uuid)
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_rc public.roll_calls; v_secret text := encode(gen_random_bytes(24), 'hex'); v_id uuid;
begin
  select * into v_rc from public.roll_calls where share_token = p_share_token;
  if v_rc.id is null or v_rc.status <> 'open' or v_rc.expires_at < now() then
    raise exception 'this roll call is closed';
  end if;
  if (select count(*) from public.roll_call_participants where roll_call_participants.roll_call_id = v_rc.id) >= 30 then
    raise exception 'roll call is full';
  end if;
  insert into public.roll_call_participants (roll_call_id, display_name, secret_hash)
  values (v_rc.id, btrim(p_name), encode(digest(v_secret, 'sha256'), 'hex'))
  returning id into v_id;
  return query select v_id, v_secret, v_rc.id;
end $$;
revoke execute on function public.join_roll_call(text, text) from public;
grant execute on function public.join_roll_call(text, text) to anon, authenticated;

create or replace function public.set_participant_status(p_participant uuid, p_secret text, p_status text) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  update public.roll_call_participants p
     set status = p_status, updated_at = now()
    from public.roll_calls rc
   where p.id = p_participant
     and p.secret_hash = encode(digest(p_secret, 'sha256'), 'hex')
     and rc.id = p.roll_call_id and rc.status = 'open';
  if not found then raise exception 'not allowed'; end if;
end $$;
revoke execute on function public.set_participant_status(uuid, text, text) from public;
grant execute on function public.set_participant_status(uuid, text, text) to anon, authenticated;

-- Read the board with the share token (what a friend's page polls on load).
create or replace function public.roll_call_board(p_share_token text)
returns table (participant_id uuid, display_name text, status text, nudged boolean, updated_at timestamptz)
language sql stable security definer set search_path = public, pg_temp as $$
  select p.id, p.display_name, p.status, p.nudged_at is not null, p.updated_at
    from public.roll_call_participants p
    join public.roll_calls rc on rc.id = p.roll_call_id
   where rc.share_token = p_share_token and rc.expires_at > now()
   order by p.display_name
$$;
revoke execute on function public.roll_call_board(text) from public;
grant execute on function public.roll_call_board(text) to anon, authenticated;

-- Scheduled sweep: at nudge time, flag everyone not home (they see it live)
-- and tell the owner who is still out.
create or replace function public.nudge_due_roll_calls() returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_rc record; v_count integer := 0; v_missing text[];
begin
  for v_rc in
    select rc.* from public.roll_calls rc
     where rc.status = 'open' and rc.nudged_at is null and rc.nudge_at <= now()
     for update skip locked
  loop
    update public.roll_call_participants set nudged_at = now()
     where roll_call_id = v_rc.id and status <> 'home';
    select array_agg(display_name order by display_name) into v_missing
      from public.roll_call_participants where roll_call_id = v_rc.id and status <> 'home';
    if v_missing is not null then
      insert into public.outbox (template, to_phone, params, member_id)
      select 'roll_call_not_home', m.phone,
             jsonb_build_object('title', v_rc.title, 'names', array_to_string(v_missing, ', ')), m.id
        from public.members m where m.id = v_rc.owner_id;
    end if;
    update public.roll_calls set nudged_at = now() where id = v_rc.id;
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;
revoke execute on function public.nudge_due_roll_calls() from public, anon, authenticated;
grant execute on function public.nudge_due_roll_calls() to service_role;
