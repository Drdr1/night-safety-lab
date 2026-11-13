-- End-to-end security and behaviour tests. Run as superuser with
--   psql -v ON_ERROR_STOP=1 -f supabase/tests/10_security_and_flows.sql
-- Each step switches to the real Supabase role (anon / authenticated / service_role)
-- with a JWT subject, so RLS and grants are exercised exactly as in production.

\set QUIET on
create schema if not exists test;
grant usage on schema test to anon, authenticated, service_role;

create or replace function test.as_user(p uuid) returns void language sql as $$
  select set_config('request.jwt.claim.sub', coalesce(p::text, ''), false)
$$;

create or replace function test.expect_error(p_sql text, p_pattern text) returns void language plpgsql as $$
begin
  begin
    execute p_sql;
  exception when others then
    if sqlerrm !~* p_pattern then
      raise exception 'expected error matching "%" but got "%" from: %', p_pattern, sqlerrm, p_sql;
    end if;
    raise notice 'ok - rejected (%)', sqlerrm;
    return;
  end;
  raise exception 'expected error matching "%" but statement succeeded: %', p_pattern, p_sql;
end $$;

create or replace function test.ok(cond boolean, msg text) returns void language plpgsql as $$
begin
  if cond is not true then raise exception 'FAILED: %', msg; end if;
  raise notice 'ok - %', msg;
end $$;
grant execute on all functions in schema test to anon, authenticated, service_role;

create table test.ctx (k text primary key, v text);
grant all on test.ctx to anon, authenticated, service_role;

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000b0b0', 'bob@example.com'),
  ('00000000-0000-0000-0000-0000000ca201', 'carol@example.com'),
  ('00000000-0000-0000-0000-0000000aaaa1', 'ops@example.com');
insert into public.team_staff values ('00000000-0000-0000-0000-0000000aaaa1', 'Night ops');

\set QUIET off
\echo '--- 1. Stripe webhook creates a gifted member and a single-use invite'
set role service_role;
do $$
declare r jsonb;
begin
  r := public.apply_billing_event('evt_1', 'checkout.session.completed', now() - interval '1 hour',
        'sub_bob', 'cus_alice', 'active', 'alice@payer.com', 'bob@example.com', 'Bob Member');
  perform test.ok((r->>'applied')::boolean and r ? 'invite_token', 'checkout creates member + invite');
  insert into test.ctx values ('bob_invite', r->>'invite_token');
  perform test.ok((select payer_email from public.subscriptions where stripe_subscription_id = 'sub_bob') = 'alice@payer.com'
                  and (select email from public.members where id = (r->>'member_id')::uuid) = 'bob@example.com',
                  'gift: payer and member are different people');
  r := public.apply_billing_event('evt_1', 'checkout.session.completed', now() - interval '1 hour',
        'sub_bob', 'cus_alice', 'active', 'alice@payer.com', 'bob@example.com', 'Bob Member');
  perform test.ok(r->>'reason' = 'duplicate', 'replayed Stripe event is ignored');

  r := public.apply_billing_event('evt_2', 'checkout.session.completed', now() - interval '1 hour',
        'sub_carol', 'cus_carol', 'active', 'carol@example.com', 'carol@example.com', 'Carol');
  insert into test.ctx values ('carol_invite', r->>'invite_token');
end $$;
reset role;

\echo '--- 2. Invite redemption: signed in, 18+, single use'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select test.expect_error(format('select public.redeem_invite(%L, (current_date - interval ''17 years'')::date)',
       (select v from test.ctx where k = 'bob_invite')), '18 or over');
select test.ok(public.redeem_invite((select v from test.ctx where k = 'bob_invite'), (current_date - interval '22 years')::date) is not null,
       'adult member redeems invite');
select test.ok(public.member_has_access(), 'bob now has active access');
select test.as_user('00000000-0000-0000-0000-0000000ca201');
select test.expect_error(format('select public.redeem_invite(%L, ''1990-01-01'')',
       (select v from test.ctx where k = 'bob_invite')), 'invalid, used or expired');
select public.redeem_invite((select v from test.ctx where k = 'carol_invite'), '1980-05-05');
reset role;

\echo '--- 3. Emergency profile and contacts are private to their owner'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
insert into public.emergency_contacts (member_id, position, name, phone)
select public.current_member_id(), p, 'Contact ' || p, '+3460000000' || p from generate_series(1, 3) p;
select test.expect_error($$insert into public.emergency_contacts (member_id, position, name, phone)
       values (public.current_member_id(), 4, 'Fourth', '+34600')$$, 'check constraint');
insert into public.emergency_profiles (member_id, languages, safe_phrase, family_alert_enabled)
values (public.current_member_id(), '{en,es}', 'blue umbrella', true);
select test.ok(true, 'member aged 22 can enable family alert');

select test.as_user('00000000-0000-0000-0000-0000000ca201');
select test.ok((select count(*) from public.emergency_contacts) = 0, 'carol cannot see bob''s contacts');
select test.ok((select count(*) from public.members) = 1, 'carol sees only her own member row');
select test.expect_error($$insert into public.emergency_profiles (member_id, family_alert_enabled)
       values (public.current_member_id(), true)$$, '18-25');
select test.expect_error($$update public.members set access_status = 'active'$$, 'permission denied');
do $$ declare n int; begin
  update public.emergency_contacts set phone = 'x'; get diagnostics n = row_count;
  perform test.ok(n = 0, 'carol cannot edit bob''s contacts');
end $$;
reset role;

\echo '--- 4. Anonymous visitors have no table access'
set role anon;
select test.as_user(null);
select test.expect_error('select * from public.members', 'permission denied');
select test.expect_error('select * from public.medical_records', 'permission denied');
select test.expect_error('select public.fire_overdue_home_by()', 'permission denied');
select test.expect_error($$select public.apply_billing_event('x','x',now(),'x','x','active','x')$$, 'permission denied');
reset role;

\echo '--- 5. Night Roll Call'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
insert into test.ctx select 'rc_token', share_token from public.create_roll_call('Tonight', now() + interval '3 hours');
reset role;

set role anon;
insert into test.ctx select 'sam', participant_id || '|' || secret from public.join_roll_call((select v from test.ctx where k = 'rc_token'), 'Sam');
insert into test.ctx select 'lea', participant_id || '|' || secret from public.join_roll_call((select v from test.ctx where k = 'rc_token'), 'Lea');
select test.expect_error(format('select public.set_participant_status(%L, %L, ''home'')',
       split_part((select v from test.ctx where k = 'sam'), '|', 1), 'wrong-secret'), 'not allowed');
select test.expect_error(format('select public.set_participant_status(%L, %L, ''home'')',
       split_part((select v from test.ctx where k = 'sam'), '|', 1), split_part((select v from test.ctx where k = 'lea'), '|', 2)),
       'not allowed');
select public.set_participant_status(split_part(v, '|', 1)::uuid, split_part(v, '|', 2), 'home') from test.ctx where k = 'sam';
select test.ok((select count(*) from public.roll_call_board((select v from test.ctx where k = 'rc_token'))) = 2,
       'friends see the board with the share link only');
select test.expect_error('select * from public.roll_call_participants', 'permission denied');
reset role;

select test.ok((select count(*) from realtime.sent where topic like 'roll_call:%') = 3, 'joins and status change broadcast live (3 events)');
select test.ok((select payload->>'status' from realtime.sent order by id desc limit 1) = 'home', 'latest broadcast carries status=home');

update public.roll_calls set nudge_at = now() - interval '1 minute';   -- time passes
set role service_role;
select test.ok(public.nudge_due_roll_calls() = 1, 'nudge sweep processes the roll call');
select test.ok(public.nudge_due_roll_calls() = 0, 'nudge sweep is idempotent');
reset role;
select test.ok((select array_agg(display_name) from public.roll_call_participants where nudged_at is not null) = '{Lea}',
       'only friends not home are nudged');
select test.ok((select params->>'names' from public.outbox where template = 'roll_call_not_home') = 'Lea',
       'owner is told who is still out');

\echo '--- 6. Home By: server-side timer and two-step escalation'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select test.expect_error('select public.set_home_by(now() + interval ''1 minute'', null)', 'between 5 minutes');
select public.set_home_by(now() + interval '2 hours',
       (select id from public.emergency_contacts where position = 1));
reset role;
update public.home_by_timers set due_at = now() - interval '1 minute';  -- member never taps Home; phone is off
set role service_role;
select test.ok(public.fire_overdue_home_by() = 1, 'overdue timer fires');
select test.ok(public.fire_overdue_home_by() = 0, 'fires exactly once');
select test.ok(public.escalate_home_by_alerts() = 0, 'contact not messaged before grace period');
reset role;
select test.ok((select count(*) from public.outbox where template in ('team_home_by_missed', 'member_home_by_check')) = 2,
       'team alerted and member messaged');
update public.alerts set opened_at = now() - interval '11 minutes' where kind = 'home_by_missed';
set role service_role;
select test.ok(public.escalate_home_by_alerts() = 1, 'escalates after grace period');
reset role;
select test.ok((select to_phone from public.outbox where template = 'contact_home_by_missed') = '+34600000001',
       'chosen contact is messaged');

\echo '--- 7. Medical data: consent, encryption, break-glass, audit'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select test.expect_error($$select public.save_my_medical('v1.a.b.c', 1::smallint, false)$$, 'consent');
select test.expect_error($$select public.save_my_medical('allergic to penicillin', 1::smallint, true)$$, 'encrypted');
select public.save_my_medical('v1.aXY.dGFn.Y2lwaGVy', 1::smallint, true);
select test.ok((select count(*) from public.medical_records) = 0, 'no direct SELECT on medical_records, even for the owner');
select test.ok(public.my_medical_ciphertext() like 'v1.%', 'owner reads own ciphertext through function');

select test.as_user('00000000-0000-0000-0000-0000000ca201');
select test.expect_error(format('select public.authorize_medical_view(%L, ''check'')',
       (select id from public.alerts limit 1)), 'team only');

select test.as_user('00000000-0000-0000-0000-0000000aaaa1');
select test.expect_error(format('select public.authorize_medical_view(%L, '' '')',
       (select id from public.alerts limit 1)), 'purpose');
select test.ok(public.authorize_medical_view((select id from public.alerts limit 1), 'Briefing 112 dispatcher') like 'v1.%',
       'team reads medical during an open alert');
select test.ok((select count(*) from public.medical_access_log) = 1, 'the view is logged');
select test.expect_error('update public.medical_access_log set purpose = ''x''', 'permission denied');
reset role;
select test.expect_error('update public.medical_access_log set purpose = ''x''', 'append-only');
select test.expect_error('delete from public.medical_access_log', 'append-only');

set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select test.ok((select count(*) from public.medical_access_log) = 1, 'member can see who viewed their medical data');
select public.mark_home();
select test.ok((select status from public.alerts where kind = 'home_by_missed') = 'resolved', 'tapping Home resolves the alert');
select test.as_user('00000000-0000-0000-0000-0000000aaaa1');
select test.expect_error(format('select public.authorize_medical_view(%L, ''late look'')',
       (select id from public.alerts limit 1)), 'only available during an active alert');
reset role;
select test.ok((select count(*) from public.incident_log) >= 4, 'incident log records the whole sequence');

\echo '--- 8. Billing changes end and restore access'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select public.set_home_by(now() + interval '2 hours', null);
reset role;
set role service_role;
select test.ok((public.apply_billing_event('evt_3', 'invoice.payment_failed', now(), 'sub_bob', 'cus_alice', 'past_due', 'alice@payer.com')->>'applied')::boolean,
       'payment failure applied');
reset role;
select test.ok((select access_status from public.members where email = 'bob@example.com') = 'ended', 'payment failure ends access');
select test.ok(not exists (select 1 from public.home_by_timers where status = 'armed'), 'armed timers are cancelled');
set role service_role;
select test.ok(public.apply_billing_event('evt_4', 'customer.subscription.updated', now() - interval '30 minutes', 'sub_bob', 'cus_alice', 'active', 'alice@payer.com')->>'reason' = 'stale',
       'out-of-order older event does not restore access');
select public.apply_billing_event('evt_5', 'customer.subscription.updated', now() + interval '1 second', 'sub_bob', 'cus_alice', 'active', 'alice@payer.com');
reset role;
select test.ok((select access_status from public.members where email = 'bob@example.com') = 'active', 'newer active event restores access');

set role authenticated;
select test.as_user('00000000-0000-0000-0000-0000000ca201');
reset role;
set role service_role;
select public.apply_billing_event('evt_6', 'customer.subscription.deleted', now() + interval '2 seconds', 'sub_carol', 'cus_carol', 'canceled', 'carol@example.com');
reset role;
set role authenticated;
select test.as_user('00000000-0000-0000-0000-0000000ca201');
select test.expect_error($$select public.create_roll_call('x', now() + interval '1 hour')$$, 'no active membership');
select test.expect_error($$select public.raise_help('call_me')$$, 'no active membership');
reset role;

\echo '--- 9. GDPR export and erasure'
set role authenticated;
select test.as_user('00000000-0000-0000-0000-00000000b0b0');
select test.ok((select public.export_my_data() ?& array['member', 'emergency_contacts', 'medical_access_log', 'medical_ciphertext']),
       'export contains every category of data');
select test.ok(not (public.export_my_data()->'member' ? 'auth_user_id'), 'export omits internal ids');
select test.expect_error($$select public.delete_my_data('yes')$$, 'does not match');
select public.delete_my_data('DELETE MY DATA');
reset role;
select test.ok(not exists (select 1 from public.members where email = 'bob@example.com')
           and not exists (select 1 from public.emergency_contacts)
           and not exists (select 1 from public.medical_records)
           and not exists (select 1 from public.medical_access_log),
       'erasure removes the member and all related data');

\echo 'ALL TESTS PASSED'
