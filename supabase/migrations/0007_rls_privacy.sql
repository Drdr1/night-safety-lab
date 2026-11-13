-- Row Level Security on every table, plus GDPR self-service (view/export, delete).
-- Supabase grants anon/authenticated ALL on public tables by default, so these
-- policies are the actual boundary. Tables with no policy for a role are closed to it.

alter table public.members                enable row level security;
alter table public.team_staff             enable row level security;
alter table public.emergency_profiles     enable row level security;
alter table public.emergency_contacts     enable row level security;
alter table public.subscriptions          enable row level security;
alter table public.billing_events         enable row level security;
alter table public.invites                enable row level security;
alter table public.alerts                 enable row level security;
alter table public.incident_log           enable row level security;
alter table public.outbox                 enable row level security;
alter table public.roll_calls             enable row level security;
alter table public.roll_call_participants enable row level security;
alter table public.home_by_timers         enable row level security;
alter table public.settings               enable row level security;
alter table public.medical_records        enable row level security;
alter table public.medical_access_log     enable row level security;

-- Belt and braces: anon has no direct table access at all (friends use RPCs).
revoke all on all tables in schema public from anon;

-- members: self read/edit of safe columns; team reads all.
create policy members_self_read on public.members for select to authenticated
  using (auth_user_id = auth.uid() or public.is_team());
create policy members_self_update on public.members for update to authenticated
  using (auth_user_id = auth.uid()) with check (auth_user_id = auth.uid());
revoke update on public.members from authenticated;
grant update (full_name, phone) on public.members to authenticated;   -- not access_status, not email

-- emergency profile + contacts: member owns, needs active access to write; team reads.
create policy ep_read on public.emergency_profiles for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());
create policy ep_write on public.emergency_profiles for all to authenticated
  using (member_id = public.current_member_id() and public.member_has_access())
  with check (member_id = public.current_member_id() and public.member_has_access());

create policy ec_read on public.emergency_contacts for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());
create policy ec_write on public.emergency_contacts for all to authenticated
  using (member_id = public.current_member_id() and public.member_has_access())
  with check (member_id = public.current_member_id() and public.member_has_access());

-- operational tables: member reads own, team reads all; writes only through functions.
create policy rc_read on public.roll_calls for select to authenticated
  using (owner_id = public.current_member_id() or public.is_team());
create policy rcp_read on public.roll_call_participants for select to authenticated
  using (public.is_team() or exists (select 1 from public.roll_calls rc
         where rc.id = roll_call_id and rc.owner_id = public.current_member_id()));
create policy hb_read on public.home_by_timers for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());
create policy alerts_read on public.alerts for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());
create policy incident_read on public.incident_log for select to authenticated
  using (public.is_team());
create policy subs_read on public.subscriptions for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());
create policy medlog_read on public.medical_access_log for select to authenticated
  using (member_id = public.current_member_id() or public.is_team());   -- members see who viewed their data
create policy team_read on public.team_staff for select to authenticated
  using (public.is_team());

revoke insert, update, delete on public.roll_calls, public.roll_call_participants, public.home_by_timers,
  public.alerts, public.incident_log, public.subscriptions, public.medical_access_log,
  public.team_staff, public.billing_events, public.invites, public.outbox, public.settings,
  public.medical_records from authenticated;
-- billing_events, invites, outbox, settings, medical_records: no policy => no direct access.

-- ---------------- GDPR self-service ----------------

-- Everything stored about the member, as one JSON document (medical stays
-- encrypted here; the server decrypts it into the download).
create or replace function public.export_my_data() returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  with me as (select * from public.members where auth_user_id = auth.uid())
  select jsonb_build_object(
    'exported_at', now(),
    'member', (select to_jsonb(me) - 'auth_user_id' from me),
    'emergency_profile', (select to_jsonb(p) from public.emergency_profiles p, me where p.member_id = me.id),
    'emergency_contacts', coalesce((select jsonb_agg(to_jsonb(c) order by c.position) from public.emergency_contacts c, me where c.member_id = me.id), '[]'),
    'home_by_timers', coalesce((select jsonb_agg(to_jsonb(h)) from public.home_by_timers h, me where h.member_id = me.id), '[]'),
    'roll_calls', coalesce((select jsonb_agg(to_jsonb(r) - 'share_token') from public.roll_calls r, me where r.owner_id = me.id), '[]'),
    'alerts', coalesce((select jsonb_agg(to_jsonb(a)) from public.alerts a, me where a.member_id = me.id), '[]'),
    'medical_access_log', coalesce((select jsonb_agg(to_jsonb(l)) from public.medical_access_log l, me where l.member_id = me.id), '[]'),
    'medical_ciphertext', (select ciphertext from public.medical_records r, me where r.member_id = me.id)
  )
$$;

-- Right to erasure: removes the member and everything that cascades from them.
-- Stripe billing records are kept by Stripe under its own legal basis.
create or replace function public.delete_my_data(p_confirm text) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if p_confirm <> 'DELETE MY DATA' then raise exception 'confirmation text does not match'; end if;
  delete from public.members where auth_user_id = auth.uid();
  if not found then raise exception 'not a member'; end if;
end $$;

revoke execute on function public.export_my_data(), public.delete_my_data(text) from public, anon;
grant execute on function public.export_my_data(), public.delete_my_data(text) to authenticated;
