import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Stripe from 'stripe';
import type pg from 'pg';
import { freshDb } from './helpers.ts';
import { handleStripeWebhook } from '../server/stripe-webhook.ts';
import { runOutboxBatch } from '../server/outbox-worker.ts';
import { reconcileSubscriptions } from '../server/reconcile.ts';

const stripe = new Stripe('sk_test_dummy');
const secret = 'whsec_test_secret';
let db: pg.Pool;

function signed(event: object) {
  const payload = JSON.stringify(event);
  return { payload, header: stripe.webhooks.generateTestHeaderString({ payload, secret }) };
}
const deps = () => ({ stripe, webhookSecret: secret, db, appUrl: 'https://app.test' });
const now = () => Math.floor(Date.now() / 1000);

before(async () => { db = await freshDb('night_safety_node_test'); });
after(async () => { await db.end(); });

test('rejects an unsigned or forged webhook', async () => {
  const { payload } = signed({ id: 'evt_x', type: 'checkout.session.completed', created: now(), data: { object: {} } });
  const r = await handleStripeWebhook(payload, 't=1,v1=deadbeef', deps());
  assert.equal(r.status, 400);
  assert.equal((await db.query('select count(*)::int n from public.members')).rows[0].n, 0);
});

test('gift checkout creates the recipient as member and queues an invite (token not echoed)', async () => {
  const { payload, header } = signed({
    id: 'evt_gift', type: 'checkout.session.completed', created: now() - 60, object: 'event',
    data: { object: {
      object: 'checkout.session', mode: 'subscription', subscription: 'sub_gift', customer: 'cus_payer',
      customer_details: { email: 'payer@example.com', name: 'Payer' },
      custom_fields: [
        { key: 'recipient_email', text: { value: 'friend@example.com' } },
        { key: 'recipient_name', text: { value: 'Friend' } },
      ],
    } },
  });
  const r = await handleStripeWebhook(payload, header, deps());
  assert.equal(r.status, 200);
  assert.equal(r.body.applied, true);
  assert.ok(!('invite_token' in r.body));
  const m = (await db.query(`select email, access_status from public.members`)).rows[0];
  assert.deepEqual(m, { email: 'friend@example.com', access_status: 'pending' });
  const o = (await db.query(`select template, params from public.outbox`)).rows[0];
  assert.equal(o.template, 'member_invite');
  assert.match(o.params.link, /^https:\/\/app\.test\/invite\/[0-9a-f]{48}$/);

  const again = await handleStripeWebhook(payload, header, deps());
  assert.equal(again.body.reason, 'duplicate');
});

test('payment failure (new API shape) ends access', async () => {
  const { payload, header } = signed({
    id: 'evt_fail', type: 'invoice.payment_failed', created: now(), object: 'event',
    data: { object: { object: 'invoice', customer: 'cus_payer', customer_email: 'payer@example.com',
      parent: { subscription_details: { subscription: 'sub_gift' } } } },
  });
  const r = await handleStripeWebhook(payload, header, deps());
  assert.equal(r.body.access, false);
  assert.equal((await db.query(`select access_status from public.members`)).rows[0].access_status, 'ended');
});

test('reconcile restores the true status when a webhook was missed', async () => {
  const fakeStripe = { subscriptions: { retrieve: async (id: string) => ({ id, status: 'active', customer: 'cus_payer' }) } } as unknown as Stripe;
  const r1 = await reconcileSubscriptions(fakeStripe, db);
  assert.deepEqual(r1, { checked: 1, changed: 1 });
  assert.equal((await db.query(`select status from public.subscriptions`)).rows[0].status, 'active');
  assert.deepEqual(await reconcileSubscriptions(fakeStripe, db), { checked: 1, changed: 0 });
});

test('outbox: WhatsApp template first, SMS fallback when WhatsApp fails', async () => {
  const calls: string[] = [];
  const fakeFetch = (async (url: string, init: RequestInit) => {
    calls.push(String(url));
    if (String(url).includes('graph.facebook.com')) {
      const body = JSON.parse(String(init.body));
      assert.equal(body.type, 'template');
      assert.equal(body.template.name, 'member_invite');
      return new Response('{"error":"rate limited"}', { status: 503 });
    }
    return new Response('{}', { status: 201 });
  }) as typeof fetch;

  await db.query(`update public.members set phone = '+34600111222'`);
  await db.query(`update public.outbox set to_phone = '+34600111222'`);
  const r = await runOutboxBatch({
    db, fetch: fakeFetch, opsPhones: ['+34600999000'],
    whatsapp: { phoneNumberId: '123', token: 't' },
    twilio: { accountSid: 'AC1', authToken: 'x', from: '+15550000000' },
  });
  assert.deepEqual(r, { sent: 1, viaSms: 1, failed: 0, retry: 0 });
  assert.ok(calls[0].includes('graph.facebook.com') && calls[1].includes('api.twilio.com'));
  const row = (await db.query(`select status, channel from public.outbox`)).rows[0];
  assert.deepEqual(row, { status: 'sent', channel: 'sms' });
});

test('outbox: total outage retries, then marks failed after max attempts', async () => {
  await db.query(`insert into public.outbox (template, to_phone, params) values ('member_home_by_check', '+34600111222', '{"name":"Friend"}')`);
  const down = (async () => new Response('down', { status: 500 })) as typeof fetch;
  const cfg = { db, fetch: down, opsPhones: [], maxAttempts: 2,
    whatsapp: { phoneNumberId: '1', token: 't' }, twilio: { accountSid: 'AC1', authToken: 'x', from: '+1' } };
  assert.equal((await runOutboxBatch(cfg)).retry, 1);
  assert.equal((await runOutboxBatch(cfg)).failed, 1);
  assert.equal((await db.query(`select status from public.outbox where template='member_home_by_check'`)).rows[0].status, 'failed');
});
