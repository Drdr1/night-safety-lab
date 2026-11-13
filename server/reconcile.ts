// Scheduled safety net for webhooks that never arrive (endpoint down,
// misconfigured destination, Stripe incident). Run hourly: it asks Stripe for
// the true status of every subscription the app knows about and applies any
// difference through the same idempotent function the webhook uses.

import type Stripe from 'stripe';
import type { Pool } from 'pg';

export async function reconcileSubscriptions(stripe: Stripe, db: Pool): Promise<{ checked: number; changed: number }> {
  const { rows } = await db.query<{ stripe_subscription_id: string; status: string }>(
    'select stripe_subscription_id, status from public.subscriptions',
  );
  let changed = 0;
  for (const row of rows) {
    const sub = await stripe.subscriptions.retrieve(row.stripe_subscription_id);
    if (sub.status === row.status) continue;
    // Deterministic per (transition, hour): re-running the job never double-applies.
    const eventId = `reconcile:${sub.id}:${row.status}->${sub.status}:${Math.floor(Date.now() / 3_600_000)}`;
    const r = await db.query(
      `select public.apply_billing_event($1, 'customer.subscription.updated', now(), $2, $3, $4, '') as r`,
      [eventId, sub.id, typeof sub.customer === 'string' ? sub.customer : sub.customer.id, sub.status],
    );
    if (r.rows[0].r.applied) changed++;
  }
  return { checked: rows.length, changed };
}
