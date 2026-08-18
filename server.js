/**
 * Avani & Co. Real Estate — backend for bamacoast.com
 *
 * This app serves the site (public/index.html) AND exposes a small API that:
 *   1. Replaces the old Claude-artifact `window.storage` calls with a real,
 *      permanent database (Supabase/Postgres) — used for leads, agents,
 *      broker passcode, and EmailJS config.
 *   2. Proxies real MLS listing data from Bridge Interactive using the
 *      Server Token, so that secret token is NEVER sent to the browser.
 *
 * Deploy target: GoDaddy Node.js Hosting (beta).
 * All secrets below are read from environment variables — set these in
 * GoDaddy's app settings after deployment. Never hard-code real values here.
 */

// Some hosting platforms have broken/unreliable outbound IPv6 routing while still
// resolving external hostnames to IPv6 addresses by default, causing Node's fetch()
// to fail with a generic "fetch failed" error. Forcing IPv4-first DNS resolution
// works around this in most cases.
require('dns').setDefaultResultOrder('ipv4first');

const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json({ limit: '2mb' }));

// ---------- Supabase (leads / agents / settings storage) ----------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
let supabase = null;
if (SUPABASE_URL && SUPABASE_SERVICE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
} else {
  console.warn('[startup] SUPABASE_URL / SUPABASE_SERVICE_KEY not set — /api/kv routes will return errors until configured.');
}
const KV_TABLE = 'kv_store';

function requireSupabase(res) {
  if (!supabase) {
    res.status(503).json({ error: 'Database not configured yet. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in the hosting environment variables.' });
    return false;
  }
  return true;
}

// GET a single key -> { key, value } or 404
app.get('/api/kv/:key', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from(KV_TABLE)
      .select('value')
      .eq('key', req.params.key)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'not found' });
    res.json({ key: req.params.key, value: data.value });
  } catch (e) {
    console.error('[GET /api/kv/:key] failed:', e, 'cause:', e.cause);
    res.status(500).json({ error: e.message, cause: e.cause ? String(e.cause) : null });
  }
});

// LIST keys by prefix -> { keys: [...] }
app.get('/api/kv', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const prefix = (req.query.prefix || '').toString();
    // escape % and _ so a prefix like "lead:" doesn't accidentally wildcard-match
    const escaped = prefix.replace(/[%_]/g, c => '\\' + c);
    const { data, error } = await supabase
      .from(KV_TABLE)
      .select('key')
      .ilike('key', `${escaped}%`);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ keys: (data || []).map(r => r.key) });
  } catch (e) {
    console.error('[GET /api/kv] failed:', e, 'cause:', e.cause);
    res.status(500).json({ error: e.message, cause: e.cause ? String(e.cause) : null });
  }
});

// SET (upsert) a key -> { ok: true }
app.post('/api/kv', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { key, value } = req.body || {};
    if (!key) return res.status(400).json({ error: 'key is required' });
    const { error } = await supabase
      .from(KV_TABLE)
      .upsert({ key, value, updated_at: new Date().toISOString() });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    console.error('[POST /api/kv] failed:', e, 'cause:', e.cause);
    res.status(500).json({ error: e.message, cause: e.cause ? String(e.cause) : null });
  }
});

// DELETE a key -> { ok: true }
app.delete('/api/kv/:key', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { error } = await supabase
      .from(KV_TABLE)
      .delete()
      .eq('key', req.params.key);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    console.error('[DELETE /api/kv/:key] failed:', e, 'cause:', e.cause);
    res.status(500).json({ error: e.message, cause: e.cause ? String(e.cause) : null });
  }
});

// ---------- MLS listings proxy (Bridge Interactive / Gulf Coast MLS) ----------
let listingsCache = { data: null, at: 0 };
// TODO: once you have the exact Bridge "Dataset" resource name for GCMLS,
// confirm this URL shape against Bridge's docs — it may need adjusting.
// Fetch a single listing by key — printed QR codes must keep working even after
// a listing falls outside the batch we cache for the homepage.
app.get('/api/listing/:key', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN;
  const dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) return res.status(503).json({ error: 'MLS not configured.' });
  const key = String(req.params.key || '').slice(0, 128);
  try {
    const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
      + `?access_token=${encodeURIComponent(token)}`
      + `&$filter=${encodeURIComponent(`ListingKey eq '${key.replace(/'/g, "''")}'`)}&$top=1`;
    const r = await fetch(url);
    if (!r.ok) return res.status(502).json({ error: `MLS API error ${r.status}` });
    const json = await r.json();
    const one = (json.value || [])[0];
    if (!one) return res.status(404).json({ error: 'Listing not found.' });
    res.json({ value: [one] });
  } catch (e) {
    console.error('[listing lookup] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/listings', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN;
  const dataset = process.env.BRIDGE_DATASET;

  if (!token || !dataset) {
    return res.json({ mock: true, value: [] });
  }

  // Bridge caps each response at 200 records, so page through with $skip until
  // we have enough. Cached for 10 minutes so we're not hammering the feed on
  // every page view — MLS data doesn't change second to second.
  const WANT = Math.min(parseInt(req.query.limit, 10) || 500, 2000);
  const PAGE = 200;

  if (listingsCache.data && Date.now() - listingsCache.at < 10 * 60 * 1000 && !req.query.fresh) {
    return res.json({ value: listingsCache.data, cached: true, count: listingsCache.data.length, totalAvailable: listingsCache.totalAvailable });
  }

  try {
    const all = [];
    let totalAvailable = null;
    for (let skip = 0; skip < WANT; skip += PAGE) {
      const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
        + `?access_token=${encodeURIComponent(token)}`
        + `&$top=${PAGE}&$skip=${skip}`
        + (skip === 0 ? '&$count=true' : '')
        + `&$filter=${encodeURIComponent("StandardStatus eq 'Active' or StandardStatus eq 'Active Under Contract' or StandardStatus eq 'Pending'")}`
        + `&$orderby=ModificationTimestamp desc`;
      const r = await fetch(url);
      if (!r.ok) {
        const text = await r.text().catch(() => '');
        if (all.length) break; // keep whatever we already have
        return res.status(502).json({ error: `MLS API error ${r.status}`, detail: text.slice(0, 500) });
      }
      const json = await r.json();
      if (skip === 0 && json['@odata.count'] != null) totalAvailable = json['@odata.count'];
      const rows = json.value || [];
      all.push(...rows);
      if (rows.length < PAGE) break; // reached the end of the feed
    }
    listingsCache = { data: all, at: Date.now(), totalAvailable };
    console.log(`[listings] fetched ${all.length} of ${totalAvailable == null ? '?' : totalAvailable} active listings from ${dataset}`);
    res.json({ value: all, count: all.length, totalAvailable, cached: false });
  } catch (e) {
    console.error('[listings] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Email notifications (via Resend's HTTP API) ----------
// Switched from direct Gmail SMTP to Resend after discovering this hosting
// platform blocks outbound SMTP entirely (ports 465 and 587 both refused
// the connection). Resend sends over regular HTTPS instead, which works
// fine here — same as our Supabase and Anthropic API calls.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = 'Avani & Co. Real Estate <notify@mail.bamacoast.com>';
let mailer = null;
if (RESEND_API_KEY) {
  mailer = {
    sendMail: async ({ to, subject, text }) => {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ from: RESEND_FROM, to, subject, text }),
      });
      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        throw new Error(`Resend API error ${res.status}: ${errText.slice(0, 300)}`);
      }
      return res.json();
    },
  };
} else {
  console.warn('[startup] RESEND_API_KEY not set — email notifications are disabled until configured.');
}

// ---------- Client accounts (favorites + saved searches) ----------
// Kept in a separate 'clients' table (never exposed via /api/kv) since it
// holds password hashes — real credentials deserve real, dedicated handling.
const crypto = require('crypto');
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(check));
}
function clientPublic(row) {
  return { id: row.id, name: row.name, email: row.email, favorites: row.favorites || [], savedSearches: row.saved_searches || [], createdAt: row.created_at || null, lastLogin: row.last_login || null };
}

app.post('/api/client/signup', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const { data: existing } = await supabase.from('clients').select('id').eq('email', normalizedEmail).maybeSingle();
    if (existing) return res.status(409).json({ error: 'An account with that email already exists — try logging in instead.' });
    const id = 'client_' + Date.now();
    const password_hash = hashPassword(password);
    const { error } = await supabase.from('clients').insert({ id, name, email: normalizedEmail, password_hash, favorites: [], saved_searches: [] });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, client: { id, name, email: normalizedEmail, favorites: [], savedSearches: [] } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/client/login', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { email, password } = req.body || {};
  const normalizedEmail = (email || '').trim().toLowerCase();
  try {
    const { data, error } = await supabase.from('clients').select('*').eq('email', normalizedEmail).maybeSingle();
    if (error || !data) return res.status(401).json({ error: 'No account found with that email.' });
    if (!verifyPassword(password, data.password_hash)) return res.status(401).json({ error: 'Incorrect password.' });
    await supabase.from('clients').update({ last_login: new Date().toISOString() }).eq('id', data.id);
    res.json({ ok: true, client: clientPublic(data) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/client/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { data, error } = await supabase.from('clients').select('*').eq('id', req.params.id).maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'Account not found.' });
  res.json({ ok: true, client: clientPublic(data) });
});

app.post('/api/client/:id/favorites', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { favorites } = req.body || {};
  const { error } = await supabase.from('clients').update({ favorites: favorites || [] }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post('/api/client/:id/saved-searches', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { savedSearches } = req.body || {};
  const { error } = await supabase.from('clients').update({ saved_searches: savedSearches || [] }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ---------- Agent/broker accounts (real email + password login) ----------
function agentPublic(row) {
  return { id: row.id, name: row.name, email: row.email, phone: row.phone || '', role: row.role, reviewLink: row.review_link || '', active: row.active !== false, lastLogin: row.last_login || null, createdAt: row.created_at || null };
}

app.post('/api/agent/setup', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, password, setupKey } = req.body || {};
  const expected = process.env.BROKER_SETUP_KEY;
  if (!expected || setupKey !== expected) return res.status(403).json({ error: 'Invalid or missing setup key.' });
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const { count } = await supabase.from('agents').select('id', { count: 'exact', head: true });
    if (count > 0) return res.status(409).json({ error: 'A broker account already exists — please log in instead.' });
    const id = 'agent_' + Date.now();
    const password_hash = hashPassword(password);
    const { error } = await supabase.from('agents').insert({ id, name, email: normalizedEmail, password_hash, role: 'broker' });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, agent: { id, name, email: normalizedEmail, phone: '', role: 'broker' } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/forgot-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const normalizedEmail = (req.body?.email || '').trim().toLowerCase();
  // Always respond the same way whether or not the email exists, so this
  // can't be used to check which emails have accounts.
  const genericReply = { ok: true, message: 'If that email has an account, a reset link has been sent.' };
  if (!normalizedEmail) return res.json(genericReply);
  try {
    const { data } = await supabase.from('agents').select('id,name,email').eq('email', normalizedEmail).maybeSingle();
    if (data) {
      const token = crypto.randomBytes(24).toString('hex');
      const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
      await supabase.from('agents').update({ reset_token: token, reset_expires: expires }).eq('id', data.id);
      if (mailer) {
        const resetUrl = `${req.protocol}://${req.get('host')}/?reset=${token}`;
        await mailer.sendMail({
          to: data.email,
          subject: 'Reset your Avani & Co. CRM password',
          text: `Hi ${data.name},\n\nSomeone requested a password reset for your Avani & Co. CRM account. If this was you, set a new password here (link expires in 1 hour):\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email.`,
        }).catch(() => {});
      }
    }
  } catch (e) {}
  res.json(genericReply);
});

app.post('/api/agent/reset-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  try {
    const { data, error } = await supabase.from('agents').select('id,reset_expires').eq('reset_token', token).maybeSingle();
    if (error || !data) return res.status(400).json({ error: 'This reset link is invalid or has already been used.' });
    if (!data.reset_expires || new Date(data.reset_expires) < new Date()) return res.status(400).json({ error: 'This reset link has expired — please request a new one.' });
    const password_hash = hashPassword(password);
    await supabase.from('agents').update({ password_hash, reset_token: null, reset_expires: null }).eq('id', data.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/login', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { email, password } = req.body || {};
  const normalizedEmail = (email || '').trim().toLowerCase();
  try {
    const { data, error } = await supabase.from('agents').select('*').eq('email', normalizedEmail).maybeSingle();
    if (error || !data) return res.status(401).json({ error: 'No account found with that email.' });
    if (!verifyPassword(password, data.password_hash)) return res.status(401).json({ error: 'Incorrect password.' });
    if (data.active === false) return res.status(403).json({ error: 'This account has been deactivated. Contact your broker.' });
    await supabase.from('agents').update({ last_login: new Date().toISOString() }).eq('id', data.id);
    res.json({ ok: true, agent: agentPublic(data) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/:id/set-active', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { active } = req.body || {};
  try {
    const { error } = await supabase.from('agents').update({ active: !!active }).eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/:id/review-link', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { reviewLink } = req.body || {};
  try {
    const { error } = await supabase.from('agents').update({ review_link: reviewLink || '' }).eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/agent/list', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase.from('agents').select('id,name,email,phone,role,review_link,active,last_login,created_at').order('name');
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, agents: (data || []).map(agentPublic) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/create', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, phone, role } = req.body || {};
  const defaultPassword = process.env.DEFAULT_AGENT_PASSWORD;
  if (!defaultPassword) return res.status(503).json({ error: 'DEFAULT_AGENT_PASSWORD is not set up yet. Add it in the hosting environment variables.' });
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required.' });
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const { data: existing } = await supabase.from('agents').select('id').eq('email', normalizedEmail).maybeSingle();
    if (existing) return res.status(409).json({ error: 'An agent with that email already exists.' });
    const id = 'agent_' + Date.now();
    const password_hash = hashPassword(defaultPassword);
    const { error } = await supabase.from('agents').insert({ id, name, email: normalizedEmail, password_hash, phone: phone || '', role: role === 'broker' ? 'broker' : 'agent' });
    if (error) return res.status(500).json({ error: error.message });
    let emailStatus = 'skipped';
    if (mailer) {
      const loginUrl = `${req.protocol}://${req.get('host')}/`;
      try {
        await mailer.sendMail({
          to: normalizedEmail,
          subject: 'Your Avani & Co. CRM login',
          text: `Hi ${name},\n\nYou've been added to the Avani & Co. Real Estate CRM. Here's how to log in:\n\n${loginUrl}\nClick "Agent Login"\n\nUsername (email): ${normalizedEmail}\nTemporary password: ${defaultPassword}\n\nOnce you're in, we recommend changing your password to something only you know — you'll find that option once logged in.\n\nWelcome aboard,\nAvani & Co. Real Estate`,
        });
        console.log(`[agent welcome email] sent successfully to ${normalizedEmail}`);
        emailStatus = 'sent';
      } catch (mailErr) {
        console.error(`[agent welcome email] FAILED to send to ${normalizedEmail}:`, mailErr.message);
        emailStatus = 'failed: ' + mailErr.message;
      }
    } else {
      console.warn(`[agent welcome email] SKIPPED for ${normalizedEmail} — mailer is not configured (RESEND_API_KEY missing).`);
    }
    res.json({ ok: true, agent: { id, name, email: normalizedEmail, phone: phone || '', role: role === 'broker' ? 'broker' : 'agent' }, emailStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/:id/change-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  try {
    const { data, error } = await supabase.from('agents').select('password_hash').eq('id', req.params.id).maybeSingle();
    if (error || !data) return res.status(404).json({ error: 'Account not found.' });
    if (!verifyPassword(currentPassword, data.password_hash)) return res.status(401).json({ error: 'Current password is incorrect.' });
    await supabase.from('agents').update({ password_hash: hashPassword(newPassword) }).eq('id', req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Broker-only override: reset any agent's password back to the shared
// default, and email them so they know how to log in again. The broker
// never loses the ability to manage agent accounts, no matter what an
// agent changes their own password to.
app.post('/api/agent/:id/reset-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const defaultPassword = process.env.DEFAULT_AGENT_PASSWORD;
  if (!defaultPassword) return res.status(503).json({ error: 'DEFAULT_AGENT_PASSWORD is not set up yet.' });
  try {
    const { data, error } = await supabase.from('agents').select('name,email').eq('id', req.params.id).maybeSingle();
    if (error || !data) return res.status(404).json({ error: 'Account not found.' });
    await supabase.from('agents').update({ password_hash: hashPassword(defaultPassword) }).eq('id', req.params.id);
    let emailStatus = 'skipped';
    if (mailer) {
      try {
        await mailer.sendMail({
          to: data.email,
          subject: 'Your Avani & Co. CRM password was reset',
          text: `Hi ${data.name},\n\nYour CRM password was reset by your broker. Your temporary password is: ${defaultPassword}\n\nPlease log in and change it to something only you know.\n\nAvani & Co. Real Estate`,
        });
        console.log(`[agent reset-password email] sent successfully to ${data.email}`);
        emailStatus = 'sent';
      } catch (mailErr) {
        console.error(`[agent reset-password email] FAILED to send to ${data.email}:`, mailErr.message);
        emailStatus = 'failed: ' + mailErr.message;
      }
    } else {
      console.warn(`[agent reset-password email] SKIPPED for ${data.email} — mailer is not configured.`);
    }
    res.json({ ok: true, emailStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/agent/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { error } = await supabase.from('agents').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// Where lead alerts go. NOTIFY_EMAIL wins; otherwise fall back to whoever the
// broker is in the agents table, so alerts keep working without extra config.
let _notifyCache = null, _notifyCachedAt = 0;
async function resolveNotifyAddress() {
  if (process.env.NOTIFY_EMAIL) return process.env.NOTIFY_EMAIL;
  if (_notifyCache && Date.now() - _notifyCachedAt < 5 * 60 * 1000) return _notifyCache;
  if (!supabase) return null;
  try {
    const { data } = await supabase.from('agents').select('email,role').eq('role', 'broker').limit(1).maybeSingle();
    if (data && data.email) { _notifyCache = data.email; _notifyCachedAt = Date.now(); return data.email; }
  } catch (e) { console.error('[lead notification] broker lookup failed:', e.message); }
  return null;
}

app.post('/api/notify-lead', async (req, res) => {
  if (!mailer) {
    return res.status(503).json({ error: 'Email is not configured yet — set RESEND_API_KEY in the hosting environment variables.' });
  }
  const notifyTo = await resolveNotifyAddress();
  if (!notifyTo) {
    console.error('[lead notification] FAILED — no destination address. Set NOTIFY_EMAIL, or make sure a broker exists in the agents table.');
    return res.status(500).json({ error: 'No notification address configured.' });
  }
  const { name, email, phone, message, source, listingLabel } = req.body || {};
  try {
    await mailer.sendMail({
      to: notifyTo,
      subject: `New lead: ${name || 'Unknown'} (${source || 'website'})`,
      text: [
        `Name: ${name || ''}`,
        `Email: ${email || ''}`,
        `Phone: ${phone || ''}`,
        `Source: ${source || ''}`,
        listingLabel ? `Listing: ${listingLabel}` : null,
        `Message: ${message || ''}`,
      ].filter(Boolean).join('\n'),
    });
    console.log(`[lead notification] sent to ${notifyTo} for lead: ${name || 'unknown'} (${source || 'website'})`);
    res.json({ ok: true, notified: notifyTo });
  } catch (e) {
    console.error('[lead notification] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Notify an agent that a lead has just been assigned to them.
// The agent's email address is looked up server-side from the agents table
// rather than trusted from the browser — the client only sends the agent id.
app.post('/api/notify-assignment', async (req, res) => {
  if (!requireSupabase(res)) return;
  if (!mailer) {
    return res.status(503).json({ error: 'Email is not configured yet.' });
  }
  const { agentId, lead } = req.body || {};
  if (!agentId) return res.status(400).json({ error: 'agentId is required' });
  const L = lead || {};
  try {
    const { data: agent, error } = await supabase
      .from('agents').select('id,name,email,active').eq('id', agentId).maybeSingle();
    if (error || !agent) return res.status(404).json({ error: 'Agent not found.' });
    if (agent.active === false) {
      console.warn(`[lead assignment email] SKIPPED — agent ${agent.email} is locked.`);
      return res.json({ ok: true, skipped: 'agent-locked' });
    }

    const lines = [
      `You've been assigned a new lead by the broker.`,
      ``,
      `Name:  ${L.name || '(not provided)'}`,
      `Email: ${L.email || '(not provided)'}`,
      `Phone: ${L.phone || '(not provided)'}`,
      L.source ? `Source: ${L.source}` : null,
      L.listingLabel ? `Listing: ${L.listingLabel}` : null,
      L.stage ? `Stage: ${L.stage}` : null,
      ``,
      `Message / notes:`,
      (L.message || L.notes || '(none)'),
      ``,
      `Log in to the CRM to follow up: https://bamacoast.com`,
    ].filter(v => v !== null);

    await mailer.sendMail({
      to: agent.email,
      subject: `New lead assigned to you: ${L.name || 'Unknown'}`,
      text: lines.join('\n'),
    });
    console.log(`[lead assignment email] sent successfully to ${agent.email}`);
    res.json({ ok: true, notified: agent.email, agentName: agent.name });
  } catch (e) {
    console.error('[lead assignment email] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- AI features (chat widget + reply drafting), via your own Anthropic API key ----------
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.warn('[startup] ANTHROPIC_API_KEY not set — AI chat and reply drafting are disabled until configured.');
}

async function callClaude(system, messages, maxTokens = 500) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-5',
      max_tokens: maxTokens,
      system,
      messages,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Anthropic API error ${res.status}: ${text.slice(0, 300)}`);
  }
  const json = await res.json();
  return (json.content || []).map(b => b.text || '').join('');
}

const CHAT_SYSTEM_PROMPT = `You are a friendly, helpful assistant for Avani & Co. Real Estate, a boutique brokerage serving Mobile & Baldwin County, Alabama (Gulf Shores, Orange Beach, Fairhope, Foley, Daphne, Mobile). Broker: Jimmy Thies, phone 251-229-3216.

Your main goal is to get the visitor's NAME and EMAIL (or phone) early, then gather the details a real agent would need. Ask ONE question at a time, in natural conversation.

GETTING CONTACT INFO — this is your top priority:
After you have answered their first question helpfully, ask for their first name. Once you have a name, use it, and within the next reply or two ask for the best email or phone number to reach them — frame it as a benefit, not a form. Good phrasings: "What's the best email for you? I'll have Jimmy send over some options that fit." or "Happy to have Jimmy follow up with specifics — what's the best number to reach you?"

Do NOT wait until you have fully qualified them before asking. Aim to have name and contact info within the first 2-3 exchanges, then keep qualifying naturally afterward.

If they decline or dodge, that's completely fine — never pressure them, never ask twice in a row, and keep helping regardless. Ask again later only if the conversation naturally opens the door.

If they seem to be BUYING: find out their general timeline (just looking / next few months / ready now), and whether they're pre-approved for financing yet (or paying cash). Don't ask both at once — work it into the conversation naturally.

If they seem to be SELLING: ask for the property address (or at least the city/area), what they think it might be worth or what prompted them to consider selling, their rough timeline, and whether there's anything unusual about the situation (inherited property, needs repairs, relocation deadline, etc.).

If they're unsure what they want, or their answers are vague, gently suggest: "Would it help to just send a quick message to Jimmy directly? He can set up a time to talk through it." and encourage them to use the "leave your contact info" option.

You do NOT have access to live MLS listings right now (the site shows sample data) — if asked about specific homes, say so honestly and encourage them to browse Featured Listings.

Keep replies short (2-4 sentences), warm, and conversational — never robotic or like a form. Never invent specific property details, prices, or availability. Once you've learned useful qualifying details (timeline, pre-approval status, or seller address/value/timeline), naturally suggest they leave their contact info so a real agent can follow up with exactly what they need.`;

app.post('/api/chat', async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI chat is not configured yet. Set ANTHROPIC_API_KEY in the hosting environment variables.' });
  }
  const { message, history } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message is required' });
  try {
    const messages = [
      ...(Array.isArray(history) ? history.slice(-10) : []),
      { role: 'user', content: message },
    ];
    const reply = await callClaude(CHAT_SYSTEM_PROMPT, messages, 400);
    res.json({ reply });
  } catch (e) {
    console.error('[POST /api/chat] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/request-review', async (req, res) => {
  if (!mailer) {
    return res.status(503).json({ error: 'Email not configured yet.' });
  }
  const { toEmail, toName, reviewLink, agentId, agentName } = req.body || {};
  if (!toEmail) return res.status(400).json({ error: 'Missing email.' });
  const siteReviewUrl = `${req.protocol}://${req.get('host')}/?leaveReview=1${agentId ? '&agent=' + encodeURIComponent(agentId) : ''}`;
  try {
    await mailer.sendMail({
      to: toEmail,
      subject: 'Would you mind leaving us a quick review?',
      text: `Hi ${toName || 'there'},\n\nThank you so much for working with ${agentName || 'Avani & Co. Real Estate'}! If you have a minute, we'd really appreciate a quick review — it helps other buyers and sellers in the area find us.\n\n${reviewLink ? `Leave a Google review: ${reviewLink}\n\n` : ''}Or leave a review directly on our site: ${siteReviewUrl}\n\nThank you again,\nJimmy Thies\nAvani & Co. Real Estate`,
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('[POST /api/request-review] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/draft-reply', async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI drafting is not configured yet. Set ANTHROPIC_API_KEY in the hosting environment variables.' });
  }
  const { name, message, source, listingLabel } = req.body || {};
  try {
    const prompt = `Draft a warm, professional, concise reply (as Jimmy Thies, Broker/Owner of Avani & Co. Real Estate) to a lead named "${name || 'there'}" who submitted this via the website (source: ${source || 'website'}${listingLabel ? ', re: ' + listingLabel : ''}):\n\n"${message || '(no message provided)'}"\n\nKeep it to 3-5 sentences. Sign off as Jimmy. Do not include a subject line, just the message body.`;
    const draft = await callClaude('You draft real estate lead follow-up emails. Be warm, concise, and professional.', [{ role: 'user', content: prompt }], 350);
    res.json({ draft });
  } catch (e) {
    console.error('[POST /api/draft-reply] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Broker first-time setup security ----------
// Prevents anyone from self-provisioning a broker account if the agent
// list ever appears empty (e.g. during a database hiccup). Only someone
// who knows this secret key can complete broker setup.
app.get('/api/broker-setup-check', (req, res) => {
  const key = req.query.key || '';
  const expected = process.env.BROKER_SETUP_KEY;
  res.json({ allowed: !!expected && key === expected });
});

// Temporary: reports this server's outbound IP address(es), needed for
// the Bridge/MLS data feed agreement's "IP addresses" question. Safe to
// remove later, but harmless to leave in.
app.get('/api/my-outbound-ip', async (req, res) => {
  try {
    const r = await fetch('https://api.ipify.org?format=json');
    const data = await r.json();
    res.json({ outboundIp: data.ip });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- MLS data (Bridge Data Output / Gulf Coast MLS) ----------
const BRIDGE_TOKEN   = process.env.BRIDGE_TOKEN;
const BRIDGE_DATASET = process.env.BRIDGE_DATASET || 'gcmls2';
const BRIDGE_BASE    = 'https://api.bridgedataoutput.com/api/v2';

async function bridgeGet(path, params = {}) {
  if (!BRIDGE_TOKEN) throw new Error('BRIDGE_TOKEN is not set.');
  const url = new URL(`${BRIDGE_BASE}/${path}`);
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== '') url.searchParams.set(k, v); });
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${BRIDGE_TOKEN}` },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Bridge ${res.status}: ${text.slice(0, 400)}`);
  try { return JSON.parse(text); } catch { throw new Error(`Bridge returned non-JSON: ${text.slice(0, 200)}`); }
}

// Read-only probe. Pulls ONE listing and reports what the feed actually contains,
// so we can see the real field names before wiring anything to the public site.
app.get('/api/mls-test', async (req, res) => {
  try {
    const data = await bridgeGet(`OData/${BRIDGE_DATASET}/Property`, { $top: 1 });
    const rows = data.value || [];
    const one = rows[0] || {};
    const fields = Object.keys(one).sort();

    // the fields the website currently expects
    const needed = ['ListingKey','ListPrice','BedroomsTotal','BathroomsTotalInteger',
                    'LivingArea','UnparsedAddress','City','StandardStatus',
                    'PropertyType','ListingId','Media','PhotosCount','ModificationTimestamp'];
    const present = needed.filter(f => f in one);
    const missing = needed.filter(f => !(f in one));

    res.json({
      ok: true,
      dataset: BRIDGE_DATASET,
      returned: rows.length,
      totalFields: fields.length,
      sitePresent: present,
      siteMissing: missing,
      allFields: fields,
      sample: one,
    });
  } catch (e) {
    console.error('[mls-test] FAILED:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    database: !!supabase,
    mlsConfigured: !!process.env.BRIDGE_TOKEN,
    mlsDataset: process.env.BRIDGE_DATASET || 'gcmls2',
    mlsConfigured: !!(process.env.BRIDGE_SERVER_TOKEN && process.env.BRIDGE_DATASET),
    emailConfigured: !!mailer,
    aiConfigured: !!ANTHROPIC_API_KEY,
  });
});

// ---------- Social preview cards for shared listing links ----------
// Mirrors the frontend's MOCK_LISTINGS — swap for real MLS data at the same
// time the frontend's fetchListings() is swapped, so both stay in sync.
const MOCK_LISTINGS = [
  {ListingKey:"AL10234561", StandardStatus:"Active", ListPrice:459900, City:"Gulf Shores", UnparsedAddress:"412 Sandpiper Ln", BedroomsTotal:3, BathroomsTotalInteger:2, LivingArea:1820},
  {ListingKey:"AL10234498", StandardStatus:"Active", ListPrice:875000, City:"Orange Beach", UnparsedAddress:"29 Perdido Cove Dr", BedroomsTotal:4, BathroomsTotalInteger:3, LivingArea:2650},
  {ListingKey:"AL10234511", StandardStatus:"Pending", ListPrice:329000, City:"Foley", UnparsedAddress:"108 Magnolia Grove Ct", BedroomsTotal:3, BathroomsTotalInteger:2, LivingArea:1540},
  {ListingKey:"AL10234477", StandardStatus:"Active", ListPrice:612500, City:"Fairhope", UnparsedAddress:"75 Bayview Terrace", BedroomsTotal:4, BathroomsTotalInteger:3, LivingArea:2380},
  {ListingKey:"AL10234550", StandardStatus:"Active", ListPrice:245000, City:"Daphne", UnparsedAddress:"1601 Chateau Dr", BedroomsTotal:2, BathroomsTotalInteger:2, LivingArea:1180},
  {ListingKey:"AL10234502", StandardStatus:"Active", ListPrice:1295000, City:"Orange Beach", UnparsedAddress:"27500 Perdido Beach Blvd #1104", BedroomsTotal:3, BathroomsTotalInteger:3, LivingArea:1980},
  {ListingKey:"AL10234533", StandardStatus:"Active", ListPrice:389000, City:"Mobile", UnparsedAddress:"22 Dauphin Landing Way", BedroomsTotal:3, BathroomsTotalInteger:2, LivingArea:1710},
  {ListingKey:"AL10234519", StandardStatus:"Pending", ListPrice:525000, City:"Gulf Shores", UnparsedAddress:"88 Waterway Village Blvd", BedroomsTotal:3, BathroomsTotalInteger:2, LivingArea:1960},
  {ListingKey:"AL10234544", StandardStatus:"Active", ListPrice:719000, City:"Fairhope", UnparsedAddress:"14 Volanta Ave", BedroomsTotal:4, BathroomsTotalInteger:3, LivingArea:2510},
];

const CRAWLER_UA_PATTERN = /facebookexternalhit|Twitterbot|LinkedInBot|Slackbot|WhatsApp|Discordbot|TelegramBot|Pinterest|redditbot|Googlebot/i;

app.get('/', (req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  const listingKey = req.query.listing;
  if (!listingKey || !CRAWLER_UA_PATTERN.test(ua)) return next(); // normal visitors -> fall through to the SPA

  const listing = MOCK_LISTINGS.find(l => l.ListingKey === listingKey);
  if (!listing) return next();

  const title = `${listing.UnparsedAddress}, ${listing.City} — $${listing.ListPrice.toLocaleString()}`;
  const desc = `${listing.BedroomsTotal} bd · ${listing.BathroomsTotalInteger} ba · ${listing.LivingArea.toLocaleString()} sqft — Avani & Co. Real Estate, Southern Sands`;
  const pageUrl = `${req.protocol}://${req.get('host')}/?listing=${encodeURIComponent(listingKey)}`;
  const imageUrl = `${req.protocol}://${req.get('host')}/assets/logo.png`;

  res.send(`<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<title>${title}</title>
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:image" content="${imageUrl}">
<meta property="og:url" content="${pageUrl}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<meta http-equiv="refresh" content="0; url=${pageUrl}">
</head><body>Redirecting to ${title}...</body></html>`);
});

app.get('/api/mock-listings', (req, res) => {
  res.json({ value: MOCK_LISTINGS });
});

// ---------- static site ----------
app.use(express.static(path.join(__dirname, 'public')));

const port = process.env.PORT || 3000;
app.listen(port, async () => {
  console.log(`Avani & Co. server running on port ${port}`);

  // Test 1: can this app reach the general internet at all?
  try {
    const r = await fetch('https://api.github.com');
    console.log('[startup] General internet test: PASSED (status ' + r.status + ')');
  } catch (e) {
    console.log('[startup] General internet test: FAILED - ' + (e && e.message));
  }

  if (supabase) {
    try {
      const { data, error } = await supabase.from(KV_TABLE).select('key').limit(1);
      if (error) {
        console.log('[startup] Supabase connectivity test FAILED (query error). Full detail: ' + JSON.stringify(error));
      } else {
        console.log('[startup] Supabase connectivity test PASSED — able to reach and query kv_store.');
      }
    } catch (e) {
      console.log('[startup] Supabase connectivity test FAILED (thrown error). Full detail: ' + JSON.stringify({
        message: e && e.message,
        cause: e && e.cause ? { code: e.cause.code, message: e.cause.message, errno: e.cause.errno } : null,
      }));
    }
  }
});
