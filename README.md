# Night Safety Lab

A work sample of the backend for a **night-out safety PWA**: friends check in on a shared Roll Call, a member's "Home By" timer alerts a human team if they don't arrive, and medical information is only readable during an active alert.

**Live simulation:** https://drdr1.github.io/night-safety-lab/ (browser-only, simulated clock)

The interesting part isn't the screens. It's the rules underneath, so they live in Postgres (Supabase) and are covered by tests that run as the real `anon` / `authenticated` / `service_role` roles.

[![ci](https://github.com/Drdr1/night-safety-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Drdr1/night-safety-lab/actions/workflows/ci.yml)

## What it does

| Feature | How it works | Where |
|---|---|---|
| **Night Roll Call** | Owner creates "Tonight". Friends join from the link with a name only (no account, no phone). Each friend gets a secret that changes only their own status. Changes go out live on a private Supabase Realtime topic. At the nudge time, a cron sweep flags everyone not home and tells the owner who's still out. | `0004_roll_call.sql` |
| **Home By** | The timer is a database row swept by `pg_cron` every minute, so a dead or offline phone still triggers it. Step 1: alert the team and message the member. Step 2 (after a grace period with no reply): message the chosen contact. "I'm home" resolves the alert. Sweeps use `FOR UPDATE SKIP LOCKED`, so overlapping runs never double-alert. | `0005_home_by.sql` |
| **Help menu** | Call me / send a team member / 112. One call opens an alert, writes the incident log and queues the team notification. | `0003_alerts_outbox.sql` |
| **Medical data** | Encrypted at field level in the server (AES-256-GCM, versioned keyring outside the DB, member id bound as AAD). Needs separate explicit consent. No RLS policy allows reading the table at all. Team reads go through `authorize_medical_view()`, which needs an **open alert** and a **reason**, and writes an **append-only access log** in the same transaction. Members can see who viewed their data. | `0006_medical.sql`, `server/medical-crypto.ts` |
| **Stripe-driven access** | Signed webhook → `apply_billing_event()`: idempotent by event id, ignores out-of-order events, supports gifting (payer ≠ member), creates a single-use 72h invite. A payment failure or cancellation ends access and stops live timers. An hourly reconcile catches webhooks that never arrived. | `0002_access_billing.sql`, `server/stripe-webhook.ts`, `server/reconcile.ts` |
| **Invite + 18+** | Invite is stored only as a SHA-256 hash, redeemable once, after OTP sign-in, with date of birth ≥ 18. | `redeem_invite()` |
| **Messaging** | Postgres only *queues* messages (`outbox`). A worker sends WhatsApp Cloud API **templates** (required outside the 24h window) and falls back to Twilio SMS, with retries. A provider outage never blocks or rolls back an alert. | `server/outbox-worker.ts` |
| **GDPR self-service** | `export_my_data()` returns everything stored about the member. `delete_my_data()` erases the member and everything that cascades from them. Family alert is limited to ages 18–25 and controlled by the member. | `0007_rls_privacy.sql` |

## Tests

```
./run-db-tests.sh      # 60+ assertions: RLS, grants, timers, escalation, billing, medical, GDPR
npm run test:node      # webhook signature/gifting/idempotency, reconcile, outbox fallback, crypto
npm run typecheck
```

Highlights of what's asserted:

- anon has **no** table access. Friends can't read the participants table and can't change another friend's status.
- A member can't see another member's contacts or change their own `access_status`.
- Medical: no direct `SELECT` even for the owner. Team gets "only available during an active alert" once the alert is resolved. Log rows can't be updated or deleted, even by a superuser session.
- Home By fires exactly once and escalates only after the grace period.
- A replayed Stripe event is ignored. An older event can't restore access after a newer payment failure.
- A ciphertext copied onto another member's row fails to decrypt. Tampering is detected. Key rotation works.

CI runs everything against a real Postgres 16. `supabase/tests/00_supabase_shim.sql` reproduces the Supabase defaults that matter for security (anon/authenticated get table grants by default, so RLS is the real boundary).

## Layout

```
supabase/migrations/   schema, RLS, functions (apply in order)
supabase/tests/        Supabase shim + end-to-end SQL tests
server/                Stripe webhook, reconcile job, outbox worker, medical crypto (TypeScript)
test/                  node:test suites
demo/                  static simulation (GitHub Pages)
```

## Not in this sample

The Next.js PWA screens, the OTP login UI and the team dashboard UI. In a real build those sit on top of the functions above. Data is EU-hostable as-is (Supabase EU region). Brand and wording are placeholders.

## Run locally

Needs Postgres 16 and Node 22.

```
npm ci
PGHOST=localhost PGUSER=postgres ./run-db-tests.sh
PGHOST=localhost PGUSER=postgres npm run test:node
```
