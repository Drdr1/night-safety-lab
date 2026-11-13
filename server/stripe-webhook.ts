// Stripe webhook -> membership access.
//
// Members pay on the marketing site (Stripe Checkout). This endpoint:
//   * verifies the Stripe signature on the raw body (reject anything else),
//   * maps the four events that matter onto apply_billing_event() in Postgres,
//     which is idempotent and ignores out-of-order events,
//   * on a new subscription, queues the single-use invite by WhatsApp and email.
//
// Gifting: the checkout collects the recipient's name/email as custom fields
// (or metadata). If absent, the payer is the member.

import type Stripe from 'stripe';
import type { Pool } from 'pg';

export interface WebhookDeps {
  stripe: Stripe;
  webhookSecret: string;
  db: Pool;                 // connection that runs as service_role
  appUrl: string;           // e.g. https://app.example.com
}

export interface WebhookResult { status: number; body: Record<string, unknown> }

const HANDLED = new Set([
  'checkout.session.completed',
  'customer.subscription.updated',
  'customer.subscription.deleted',
  'invoice.payment_failed',
]);

export async function handleStripeWebhook(rawBody: string | Buffer, signature: string | undefined, deps: WebhookDeps): Promise<WebhookResult> {
  let event: Stripe.Event;
  try {
    event = await deps.stripe.webhooks.constructEventAsync(rawBody, signature ?? '', deps.webhookSecret);
  } catch {
    return { status: 400, body: { error: 'invalid signature' } };
  }
  if (!HANDLED.has(event.type)) return { status: 200, body: { ignored: event.type } };

  const p = await toBillingParams(event, deps.stripe);
  if (!p) return { status: 200, body: { ignored: 'not a subscription event' } };

  const { rows } = await deps.db.query(
    `select public.apply_billing_event($1,$2,to_timestamp($3),$4,$5,$6,$7,$8,$9,to_timestamp($10)) as r`,
    [event.id, event.type, event.created, p.subscriptionId, p.customerId, p.status, p.payerEmail,
     p.memberEmail, p.memberName, p.periodEnd],
  );
  const result = rows[0].r as { applied: boolean; member_id?: string; invite_token?: string; reason?: string };

  if (result.invite_token && result.member_id) {
    const link = `${deps.appUrl}/invite/${result.invite_token}`;
    await deps.db.query(
      `insert into public.outbox (template, to_phone, params, member_id)
       select 'member_invite', m.phone, jsonb_build_object('name', m.full_name, 'link', $2::text, 'email', m.email), m.id
         from public.members m where m.id = $1`,
      [result.member_id, link],
    );
  }
  // Never echo the token back to Stripe's dashboard logs.
  const { invite_token: _omit, ...safe } = result;
  return { status: 200, body: safe };
}

interface BillingParams {
  subscriptionId: string; customerId: string; status: string; payerEmail: string;
  memberEmail: string | null; memberName: string | null; periodEnd: number | null;
}

function idOf(x: string | { id: string } | null | undefined): string | null {
  return typeof x === 'string' ? x : x?.id ?? null;
}

// current_period_end moved to subscription items in newer Stripe API versions.
function periodEndOf(sub: Stripe.Subscription): number | null {
  const anySub = sub as unknown as { current_period_end?: number; items?: { data?: Array<{ current_period_end?: number }> } };
  return anySub.current_period_end ?? anySub.items?.data?.[0]?.current_period_end ?? null;
}

async function toBillingParams(event: Stripe.Event, stripe: Stripe): Promise<BillingParams | null> {
  switch (event.type) {
    case 'checkout.session.completed': {
      const s = event.data.object as Stripe.Checkout.Session;
      const subId = idOf(s.subscription as string | null);
      if (s.mode !== 'subscription' || !subId) return null;
      const field = (key: string) => s.custom_fields?.find((f) => f.key === key)?.text?.value ?? null;
      const payerEmail = s.customer_details?.email ?? s.customer_email ?? '';
      return {
        subscriptionId: subId,
        customerId: idOf(s.customer as string | null) ?? '',
        status: 'active',
        payerEmail,
        memberEmail: field('recipient_email') ?? s.metadata?.recipient_email ?? payerEmail,
        memberName: field('recipient_name') ?? s.metadata?.recipient_name ?? s.customer_details?.name ?? null,
        periodEnd: null,
      };
    }
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const sub = event.data.object as Stripe.Subscription;
      return {
        subscriptionId: sub.id, customerId: idOf(sub.customer as string) ?? '',
        status: event.type === 'customer.subscription.deleted' ? 'canceled' : sub.status,
        payerEmail: '', memberEmail: null, memberName: null, periodEnd: periodEndOf(sub),
      };
    }
    case 'invoice.payment_failed': {
      const inv = event.data.object as Stripe.Invoice & { subscription?: string | null };
      // Newer API versions nest the subscription under parent.subscription_details.
      const subId = idOf(inv.subscription ?? (inv as any).parent?.subscription_details?.subscription);
      if (!subId) return null;
      return {
        subscriptionId: subId, customerId: idOf(inv.customer as string) ?? '', status: 'past_due',
        payerEmail: inv.customer_email ?? '', memberEmail: null, memberName: null, periodEnd: null,
      };
    }
  }
  void stripe;
  return null;
}
