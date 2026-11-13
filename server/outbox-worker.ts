// Delivers queued messages: WhatsApp Cloud API template first, Twilio SMS fallback.
//
// Why templates: business-initiated WhatsApp messages outside the 24-hour
// customer-service window must use pre-approved templates. Alerts and
// check-ins are exactly that, so every outbox row names a template.
//
// Rows are claimed with FOR UPDATE SKIP LOCKED, so several workers (or an
// overlapping cron run) never send the same alert twice.

import type { Pool } from 'pg';

type Fetch = typeof fetch;

export interface WorkerConfig {
  db: Pool;
  fetch?: Fetch;
  whatsapp: { phoneNumberId: string; token: string; apiVersion?: string };
  twilio: { accountSid: string; authToken: string; from: string };
  opsPhones: string[];                // team on-call numbers for to_phone = null
  maxAttempts?: number;
}

// Template name -> ordered body parameters. Wording lives in Meta Business Manager.
export const TEMPLATES: Record<string, string[]> = {
  member_invite: ['name', 'link'],
  member_home_by_check: ['name'],
  contact_home_by_missed: ['contact', 'member'],
  team_home_by_missed: ['member', 'due'],
  team_help_request: ['member', 'kind'],
  team_member_home: ['alert'],
  roll_call_not_home: ['title', 'names'],
};

interface OutboxRow { id: number; template: string; to_phone: string | null; params: Record<string, string>; attempts: number }

export function smsText(row: Pick<OutboxRow, 'template' | 'params'>): string {
  const p = row.params;
  switch (row.template) {
    case 'member_invite': return `Hi ${p.name}, your membership is ready. Open your invite: ${p.link}`;
    case 'member_home_by_check': return `Hi ${p.name}, you're past your Home By time. Reply or tap Home in the app.`;
    case 'contact_home_by_missed': return `Hi ${p.contact}, ${p.member} hasn't checked in home and isn't replying. Our team is on it and will contact you.`;
    case 'roll_call_not_home': return `${p.title}: still not home: ${p.names}`;
    default: return `[${row.template}] ${JSON.stringify(p)}`;
  }
}

async function sendWhatsApp(cfg: WorkerConfig, to: string, row: OutboxRow): Promise<void> {
  const f = cfg.fetch ?? fetch;
  const names = TEMPLATES[row.template];
  if (!names) throw new Error(`no template mapping for ${row.template}`);
  const res = await f(`https://graph.facebook.com/${cfg.whatsapp.apiVersion ?? 'v21.0'}/${cfg.whatsapp.phoneNumberId}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${cfg.whatsapp.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp', to, type: 'template',
      template: {
        name: row.template, language: { code: 'en' },
        components: [{ type: 'body', parameters: names.map((n) => ({ type: 'text', text: String(row.params[n] ?? '') })) }],
      },
    }),
  });
  if (!res.ok) throw new Error(`whatsapp ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

async function sendSms(cfg: WorkerConfig, to: string, row: OutboxRow): Promise<void> {
  const f = cfg.fetch ?? fetch;
  const res = await f(`https://api.twilio.com/2010-04-01/Accounts/${cfg.twilio.accountSid}/Messages.json`, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${cfg.twilio.accountSid}:${cfg.twilio.authToken}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ To: to, From: cfg.twilio.from, Body: smsText(row) }),
  });
  if (!res.ok) throw new Error(`sms ${res.status}`);
}

/** Processes one batch. Returns counts. Call every few seconds or from a cron. */
export async function runOutboxBatch(cfg: WorkerConfig, batchSize = 20) {
  const maxAttempts = cfg.maxAttempts ?? 3;
  const { rows } = await cfg.db.query<OutboxRow>(
    `update public.outbox set status = 'sending', attempts = attempts + 1
      where id in (select id from public.outbox where status = 'pending'
                    order by created_at limit $1 for update skip locked)
      returning id, template, to_phone, params, attempts`, [batchSize]);

  const out = { sent: 0, viaSms: 0, failed: 0, retry: 0 };
  for (const row of rows) {
    const recipients = row.to_phone ? [row.to_phone] : cfg.opsPhones;
    let channel: 'whatsapp' | 'sms' | null = null;
    let lastError = '';
    for (const to of recipients) {
      try { await sendWhatsApp(cfg, to, row); channel ??= 'whatsapp'; continue; } catch (e) { lastError = String(e); }
      try { await sendSms(cfg, to, row); channel = 'sms'; } catch (e) { lastError += ' | ' + String(e); }
    }
    if (channel) {
      await cfg.db.query(`update public.outbox set status='sent', channel=$2, sent_at=now(), last_error=null where id=$1`, [row.id, channel]);
      out.sent++; if (channel === 'sms') out.viaSms++;
    } else {
      const final = row.attempts >= maxAttempts;
      await cfg.db.query(`update public.outbox set status=$2, last_error=$3 where id=$1`, [row.id, final ? 'failed' : 'pending', lastError]);
      if (final) out.failed++; else out.retry++;
    }
  }
  return out;
}
