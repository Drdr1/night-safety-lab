-- Supabase-only wiring, skipped automatically where the extensions are absent
-- (local Postgres / CI).

-- Sweeps every minute. pg_cron is available on Supabase (Database > Extensions).
do $$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_cron') then
    create extension if not exists pg_cron;
    perform cron.schedule('home-by-fire',     '* * * * *', 'select public.fire_overdue_home_by()');
    perform cron.schedule('home-by-escalate', '* * * * *', 'select public.escalate_home_by_alerts()');
    perform cron.schedule('roll-call-nudge',  '* * * * *', 'select public.nudge_due_roll_calls()');
  end if;
end $$;

-- Private Realtime broadcast topics. A roll call's topic is roll_call:<uuid>;
-- the uuid is only handed out by join_roll_call / create_roll_call, so knowing
-- the topic is the capability. Team staff can listen to every topic.
do $$
begin
  if to_regclass('realtime.messages') is not null then
    execute $p$
      create policy roll_call_listen on realtime.messages for select to anon, authenticated
      using (extension = 'broadcast' and realtime.topic() like 'roll_call:%')
    $p$;
  end if;
end $$;
