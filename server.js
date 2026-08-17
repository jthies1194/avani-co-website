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
const nodemailer = require('nodemailer');

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
// TODO: once you have the exact Bridge "Dataset" resource name for GCMLS,
// confirm this URL shape against Bridge's docs — it may need adjusting.
app.get('/api/listings', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN;
  const dataset = process.env.BRIDGE_DATASET;

  if (!token || !dataset) {
    // Not configured yet — tell the frontend so it can fall back to sample data.
    return res.json({ mock: true, value: [] });
  }

  try {
    const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property?access_token=${encodeURIComponent(token)}&$top=50`;
    const r = await fetch(url);
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      return res.status(502).json({ error: `MLS API error ${r.status}`, detail: text.slice(0, 500) });
    }
    const json = await r.json();
    res.json(json);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Lead email notifications (via your own Gmail account) ----------
let mailer = null;
if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
} else {
  console.warn('[startup] GMAIL_USER / GMAIL_APP_PASSWORD not set — lead email notifications are disabled until configured.');
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
  return { id: row.id, name: row.name, email: row.email, favorites: row.favorites || [], savedSearches: row.saved_searches || [] };
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
  return { id: row.id, name: row.name, email: row.email, phone: row.phone || '', role: row.role };
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
          from: `"Avani & Co. Website" <${process.env.GMAIL_USER}>`,
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
    res.json({ ok: true, agent: agentPublic(data) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/agent/list', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase.from('agents').select('id,name,email,phone,role').order('name');
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, agents: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/create', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { name, email, password, phone, role } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const normalizedEmail = email.trim().toLowerCase();
  try {
    const { data: existing } = await supabase.from('agents').select('id').eq('email', normalizedEmail).maybeSingle();
    if (existing) return res.status(409).json({ error: 'An agent with that email already exists.' });
    const id = 'agent_' + Date.now();
    const password_hash = hashPassword(password);
    const { error } = await supabase.from('agents').insert({ id, name, email: normalizedEmail, password_hash, phone: phone || '', role: role === 'broker' ? 'broker' : 'agent' });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true, agent: { id, name, email: normalizedEmail, phone: phone || '', role: role === 'broker' ? 'broker' : 'agent' } });
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

app.post('/api/notify-lead', async (req, res) => {
  if (!mailer) {
    return res.status(503).json({ error: 'Email not configured yet. Set GMAIL_USER and GMAIL_APP_PASSWORD in the hosting environment variables.' });
  }
  const notifyTo = process.env.NOTIFY_EMAIL || process.env.GMAIL_USER;
  const { name, email, phone, message, source, listingLabel } = req.body || {};
  try {
    await mailer.sendMail({
      from: `"Avani & Co. Website" <${process.env.GMAIL_USER}>`,
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
    res.json({ ok: true });
  } catch (e) {
    console.error('[POST /api/notify-lead] failed:', e.message);
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

Your main goal in every conversation is to figure out why the visitor is here and gently gather the details a real agent would need to follow up well — without ever feeling like an interrogation. Ask ONE question at a time, in natural conversation.

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
  const { toEmail, toName, reviewLink } = req.body || {};
  if (!toEmail || !reviewLink) return res.status(400).json({ error: 'Missing email or review link.' });
  try {
    await mailer.sendMail({
      from: `"Avani & Co. Real Estate" <${process.env.GMAIL_USER}>`,
      to: toEmail,
      subject: 'Would you mind leaving us a quick review?',
      text: `Hi ${toName || 'there'},\n\nThank you so much for working with Avani & Co. Real Estate! If you have a minute, we'd really appreciate a quick review — it helps other buyers and sellers in the area find us.\n\n${reviewLink}\n\nThank you again,\nJimmy Thies\nAvani & Co. Real Estate`,
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

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    database: !!supabase,
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
