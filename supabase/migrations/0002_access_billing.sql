-- Access control driven by Stripe. The app takes no payments; the website's
-- Stripe checkout is the source of truth. Webhooks apply changes immediately,
-- and a scheduled reconcile (server/reconcile.ts) catches events Stripe never delivered.

create table public.subscriptions (
  stripe_subscription_id text primary key,
  stripe_customer_id     text not null,
  payer_email            text not null,          -- may differ from the member (gifting)
  member_id              uuid not null references public.members (id) on delete cascade,
  status                 text not null,
  current_period_end     timestamptz,
  updated_at             timestamptz not null default now()
);

-- Idempotency: Stripe retries and can deliver out of order.
create table public.billing_events (
  stripe_event_id text primary key,
  type            text not null,
  created_at      timestamptz not null,          -- Stripe event time, used to ignore stale events
  processed_at    timestamptz not null default now()
);

create table public.invites (
  token_hash  text primary key,                  -- sha256 of the token; raw token only ever in the link
  member_id   uuid not null references public.members (id) on delete cascade,
  expires_at  timestamptz not null,
  used_at     timestamptz
);

-- Statuses that keep access. Anything else ends it.
create or replace function public.status_grants_access(p_status text) returns boolean
language sql immutable as $$ select p_status in ('active', 'trialing') $$;

/*
  apply_billing_event — called only by the webhook handler / reconcile job (service_role).
  Returns jsonb: { applied, member_id, invite_token? }.
  invoice.payment_failed ends access at once (the brief: "access ends if a payment fails").
*/
create or replace function public.apply_billing_event(
  p_event_id        text,
  p_type            text,
  p_event_created   timestamptz,
  p_subscription_id text,
  p_customer_id     text,
  p_status          text,
  p_payer_email     text,
  p_member_email    text default null,
  p_member_name     text default null,
  p_period_end      timestamptz default null
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_member uuid;
  v_sub    public.subscriptions%rowtype;
  v_token  text;
  v_grants boolean;
begin
  -- 1. idempotency
  insert into public.billing_events (stripe_event_id, type, created_at)
  values (p_event_id, p_type, p_event_created)
  on conflict do nothing;
  if not found then
    return jsonb_build_object('applied', false, 'reason', 'duplicate');
  end if;

  select * into v_sub from public.subscriptions where stripe_subscription_id = p_subscription_id for update;

  -- 2. new subscription: create the member (recipient for gifts) and a single-use invite
  if v_sub.stripe_subscription_id is null then
    if p_type <> 'checkout.session.completed' then
      return jsonb_build_object('applied', false, 'reason', 'unknown_subscription');
    end if;
    insert into public.members (full_name, email, access_status)
    values (coalesce(p_member_name, 'Member'), coalesce(p_member_email, p_payer_email), 'pending')
    on conflict (lower(email)) do update set access_status = 'pending', access_ended_reason = null
    returning id into v_member;

    insert into public.subscriptions (stripe_subscription_id, stripe_customer_id, payer_email, member_id, status, current_period_end, updated_at)
    values (p_subscription_id, p_customer_id, p_payer_email, v_member, p_status, p_period_end, p_event_created);

    v_token := encode(gen_random_bytes(24), 'hex');
    insert into public.invites (token_hash, member_id, expires_at)
    values (encode(digest(v_token, 'sha256'), 'hex'), v_member, now() + interval '72 hours');

    return jsonb_build_object('applied', true, 'member_id', v_member, 'invite_token', v_token);
  end if;

  v_member := v_sub.member_id;

  -- 3. ignore events older than the last one applied to this subscription
  if p_event_created < v_sub.updated_at then
    return jsonb_build_object('applied', false, 'reason', 'stale', 'member_id', v_member);
  end if;

  if p_type = 'invoice.payment_failed' then
    p_status := 'payment_failed';
  end if;

  update public.subscriptions
     set status = p_status,
         current_period_end = coalesce(p_period_end, current_period_end),
         updated_at = p_event_created
   where stripe_subscription_id = p_subscription_id;

  v_grants := public.status_grants_access(p_status);
  update public.members
     set access_status = case
           when v_grants and auth_user_id is not null then 'active'
           when v_grants then 'pending'
           else 'ended' end,
         access_ended_reason = case when v_grants then null else p_status end
   where id = v_member;

  -- Ending access also stops anything that would alert on the member's behalf.
  if not v_grants then
    update public.home_by_timers set status = 'cancelled' where member_id = v_member and status = 'armed';
    update public.roll_calls set status = 'closed' where owner_id = v_member and status = 'open';
  end if;

  return jsonb_build_object('applied', true, 'member_id', v_member, 'access', v_grants);
end $$;

revoke execute on function public.apply_billing_event(text, text, timestamptz, text, text, text, text, text, text, timestamptz) from public, anon, authenticated;
grant execute on function public.apply_billing_event(text, text, timestamptz, text, text, text, text, text, text, timestamptz) to service_role;

/*
  redeem_invite — called after the person logs in with a one-time code.
  Single use, expiring, and the member must confirm they are 18+.
*/
create or replace function public.redeem_invite(p_token text, p_date_of_birth date) returns uuid
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_inv public.invites%rowtype; v_status text;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;

  select * into v_inv from public.invites
   where token_hash = encode(digest(p_token, 'sha256'), 'hex') for update;
  if v_inv.token_hash is null or v_inv.used_at is not null or v_inv.expires_at < now() then
    raise exception 'invite is invalid, used or expired';
  end if;
  if p_date_of_birth is null or age(current_date, p_date_of_birth) < interval '18 years' then
    raise exception 'members must be 18 or over';
  end if;

  select status into v_status from public.subscriptions where member_id = v_inv.member_id
   order by updated_at desc limit 1;

  update public.invites set used_at = now() where token_hash = v_inv.token_hash;
  update public.members
     set auth_user_id = auth.uid(),
         date_of_birth = p_date_of_birth,
         access_status = case when public.status_grants_access(v_status) then 'active' else 'ended' end
   where id = v_inv.member_id;
  return v_inv.member_id;
end $$;

revoke execute on function public.redeem_invite(text, date) from public, anon;
grant execute on function public.redeem_invite(text, date) to authenticated;
