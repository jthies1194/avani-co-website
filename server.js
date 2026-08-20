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

const crypto = require('crypto');
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// ---------- brokerage identity ----------
// The trade name exactly as licensed with the Alabama Real Estate Commission.
// AREC Rule 790-X-3-.16 requires this name, not an abbreviation, on advertising.
// The LLC below is the legal entity and belongs only in a copyright notice.
const BROKERAGE_NAME = 'Avani & Co Real Estate Southern Sands';
const BROKERAGE_LEGAL_ENTITY = 'Avani & Co Real Estate LLC';
const BROKERAGE_PHONE = '251-229-3216';

const app = express();
// Flyer PDFs run to a few megabytes, so the old 2mb ceiling rejected them.
app.use(express.json({ limit: '14mb' }));

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
// ---------- server-side sessions ----------
// Until now every /api/kv call was unauthenticated: anyone who knew the URL
// could read every lead, commission and agent profile. Sessions fix that, and
// let the server enforce who may see what rather than trusting the browser.
const SESSION_HOURS = 12;

function newToken() {
  return 'sess_' + Date.now().toString(36) + '_' +
    Array.from({ length: 4 }, () => Math.random().toString(36).slice(2, 10)).join('');
}

async function createSession(agent) {
  const token = newToken();
  const rec = {
    agentId: agent.id, role: agent.role || 'agent', name: agent.name || '',
    email: agent.email || '',            // so replies to a sent flyer reach the agent
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_HOURS * 3600 * 1000).toISOString(),
  };
  await setSetting('session:' + token, rec);
  return { token, expiresAt: rec.expiresAt };
}

async function getSession(req) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (!token) return null;
  const rec = await getSetting('session:' + token);
  if (!rec || !rec.agentId) return null;
  if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) return null;
  return rec;
}

function isStaff(sess) { return sess && (sess.role === 'broker' || sess.role === 'admin'); }

/* Client accounts get their own tokens, entirely separate from agent sessions.
   Before this, a client id was the only credential and ids are millisecond
   timestamps — so anyone could walk the range and read every client's name,
   email, favorites and saved searches. */
const CLIENT_SESSION_DAYS = 30;

async function createClientSession(clientId) {
  const token = 'cli_' + Date.now().toString(36) + '_' +
    crypto.randomBytes(18).toString('hex');
  await setSetting('clientSession:' + token, {
    clientId,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + CLIENT_SESSION_DAYS * 86400 * 1000).toISOString(),
  });
  return token;
}

async function getClientSession(req) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (!token || !token.startsWith('cli_')) return null;
  const rec = await getSetting('clientSession:' + token);
  if (!rec || !rec.clientId) return null;
  if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) return null;
  return rec;
}

/* A client may only touch their own record. Staff may look, for support. */
async function requireClientSelf(req, res, id) {
  const cs = await getClientSession(req);
  if (cs && cs.clientId === id) return true;
  const sess = await getSession(req);
  if (isStaff(sess)) return true;
  console.warn(`[security] blocked unauthenticated access to client ${id}`);
  res.status(403).json({ error: 'Not permitted.' });
  return false;
}

async function requireSession(req, res) {
  const sess = await getSession(req);
  if (!sess) {
    res.status(401).json({ error: 'Sign in to access this.' });
    return null;
  }
  return sess;
}

/* What an agent may touch. Staff (broker/admin) are unrestricted. */
/* Admins handle commissions, expenses and accounts — not leads. Client contact
   details are deliberately out of their reach so they can't be passed around. */
/* Public visitors have no session, but they must still be able to submit a
   lead and read the handful of settings the public site needs. Anything else
   stays behind authentication. */
function publicWriteAllowed(key) {
  return String(key || '').startsWith('lead:');
}
const PUBLIC_READ_KEYS = ['settings:viewLimit', 'settings:testimonials', 'settings:reviewLink'];
function publicReadAllowed(key) {
  return PUBLIC_READ_KEYS.includes(String(key || ''));
}

function adminBlocked(key) {
  const k = String(key || '');
  return k.startsWith('lead:') || k === 'settings:leadArchive';
}

function keyAllowedForAgent(key, sess, write) {
  const k = String(key || '');
  // their own profile only
  if (k.startsWith('agentProfile:')) return k === 'agentProfile:' + sess.agentId;
  // plans and plan history are read-only to agents
  if (k === 'settings:agentPlans' || k === 'settings:agentPlanHistory') return !write;  // staff bypass this check entirely
  // the official ledger is broker-written; agents read a filtered copy
  if (k === 'settings:closedDeals') return !write;
  // admin machinery is off limits
  if (k === 'settings:adminRequests' || k === 'settings:adminBypass') return false;
  if (k.startsWith('session:') || k.startsWith('clientSession:')) return false;
  // Anything not named above was previously readable by any signed-in agent —
  // including settings:leadArchive, the entire archived lead history. Shared
  // keys are now allowlisted, so a new key is private until it is listed.
  const AGENT_READABLE = new Set([
    'settings:viewLimit', 'settings:testimonials', 'settings:reviewLink',
    'settings:agentPlans', 'settings:agentPlanHistory', 'settings:closedDeals',
    'settings:expenses', 'settings:dealSubmissions', 'settings:officeCalendar',
    'settings:resourceLinks', 'settings:marketingPolicy',
  ]);
  if (k.startsWith('settings:')) return AGENT_READABLE.has(k) && !write;
  if (k.startsWith('lead:')) return true;                 // ownership checked separately
  if (k.startsWith('agentAlerts:')) return k === 'agentAlerts:' + sess.agentId;
  if (k.startsWith('agentPublic:')) return true;          // public profile data
  // Marketing projects are per agent: marketing:<agentId>:<projectId>.
  // Staff bypass this function entirely, which is how the broker sees all of them.
  if (k.startsWith('marketing:')) return k.startsWith('marketing:' + sess.agentId + ':');
  return true;
}

/* Trim shared arrays down to the requesting agent's own rows. */
function scopeValueForAgent(key, value, sess) {
  if (!Array.isArray(value)) return value;
  if (key === 'settings:closedDeals' || key === 'settings:expenses' || key === 'settings:dealSubmissions') {
    return value.filter(v => v && v.agentId === sess.agentId);
  }
  return value;
}

app.get('/api/kv/:key', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await getSession(req);
  if (!sess) {
    if (!publicReadAllowed(req.params.key)) {
      return res.status(401).json({ error: 'Sign in to access this.' });
    }
  }
  if (sess && sess.role === 'admin' && adminBlocked(req.params.key)) {
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  if (sess && !isStaff(sess) && !keyAllowedForAgent(req.params.key, sess, false)) {
    return res.status(403).json({ error: 'Not permitted.' });
  }
  if (String(req.params.key || '').match(/^(session|clientSession):/)) {
    console.warn(`[security] blocked direct read of a session token`);
    return res.status(403).json({ error: 'Not permitted.' });
  }
  try {
    const { data, error } = await supabase
      .from(KV_TABLE)
      .select('value')
      .eq('key', req.params.key)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'not found' });

    // Individual leads are stored one per key, so array scoping doesn't cover
    // them — an agent could otherwise read any lead by its id.
    if (sess && !isStaff(sess) && String(req.params.key).startsWith('lead:')) {
      const owner = data.value && data.value.assignedAgentId;
      if (owner && owner !== sess.agentId) {
        console.warn(`[security] agent ${sess.agentId} blocked reading lead owned by ${owner}`);
        return res.status(403).json({ error: 'Not your lead.' });
      }
    }

    const value = (!sess || isStaff(sess)) ? data.value : scopeValueForAgent(req.params.key, data.value, sess);
    res.json({ key: req.params.key, value });
  } catch (e) {
    console.error('[GET /api/kv/:key] failed:', e, 'cause:', e.cause);
    res.status(500).json({ error: e.message, cause: e.cause ? String(e.cause) : null });
  }
});

// LIST keys by prefix -> { keys: [...] }
app.get('/api/kv', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  {
    const prefix = (req.query.prefix || '').toString();
    if (sess.role === 'admin' && adminBlocked(prefix)) {
      return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
    }
    if (!isStaff(sess) && (prefix.startsWith('session:') || prefix.startsWith('agentProfile:'))) {
      return res.status(403).json({ error: 'Not permitted.' });
    }
    // Nobody lists session tokens, staff included. An admin who could enumerate
    // these could read one and assume the broker's session, defeating every
    // broker-account protection below.
    if (prefix.startsWith('session:') || prefix.startsWith('clientSession:')) {
      console.warn(`[security] ${sess.agentId} (${sess.role}) blocked from listing session tokens`);
      return res.status(403).json({ error: 'Not permitted.' });
    }
  }
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
  const sess = await getSession(req);
  if (!sess) {
    // a visitor submitting an inquiry — leads only, nothing else
    if (!publicWriteAllowed((req.body || {}).key)) {
      return res.status(401).json({ error: 'Sign in to access this.' });
    }
  }
  if (sess && sess.role === 'admin' && adminBlocked((req.body || {}).key)) {
    console.warn(`[security] admin ${sess.agentId} blocked from writing a lead`);
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  if (sess && !isStaff(sess) && !keyAllowedForAgent((req.body || {}).key, sess, true)) {
    console.warn(`[security] agent ${sess.agentId} blocked writing ${(req.body||{}).key}`);
    return res.status(403).json({ error: 'Not permitted.' });
  }
  // Writing a lead: it has to already be theirs. Passing it to a colleague is
  // allowed — that's the transfer — but taking someone else's is not.
  if (sess && !isStaff(sess) && String((req.body || {}).key).startsWith('lead:')) {
    try {
      const { data: existing } = await supabase.from('kv_store')
        .select('value').eq('key', (req.body || {}).key).maybeSingle();
      const currentOwner = existing && existing.value && existing.value.assignedAgentId;
      if (currentOwner && currentOwner !== sess.agentId) {
        console.warn(`[security] agent ${sess.agentId} blocked writing a lead owned by ${currentOwner}`);
        return res.status(403).json({ error: 'Not your lead.' });
      }
    } catch (e) { /* new lead, nothing to compare */ }
  }
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
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role === 'admin' && adminBlocked(req.params.key)) {
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  if (!isStaff(sess) && !keyAllowedForAgent(req.params.key, sess, true)) {
    return res.status(403).json({ error: 'Not permitted.' });
  }
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
// What the public homepage shows by default: genuinely available listings.
// Pending and under-contract are still searchable via the Status filter.
const ACTIVE_ONLY = "StandardStatus eq 'Active'";
const STATUS_CLAUSE = "(StandardStatus eq 'Active' or StandardStatus eq 'Active Under Contract' or StandardStatus eq 'Pending')";

// Avani's market is the Baldwin County coast. The raw feed is newest-first,
// which buries beach listings under Mobile County volume — so we pull Baldwin
// explicitly, then rank what comes back by how close it is to home.
const BEACH_CITIES = ['gulf shores','orange beach','fort morgan','perdido beach','ono island',
                      'bon secour','perdido key','gulf highlands','laguna key'];
const EASTERN_SHORE = ['fairhope','daphne','spanish fort','point clear','montrose','magnolia springs',
                       'barnwell','belforest','battles wharf','malbis'];

function marketRank(row) {
  const city = String(row.City || '').toLowerCase().trim();
  const county = String(row.CountyOrParish || '').toLowerCase();
  if (BEACH_CITIES.includes(city)) return 0;          // the beach first
  if (EASTERN_SHORE.includes(city)) return 1;         // then the bay
  if (county.startsWith('baldwin')) return 2;         // rest of Baldwin
  if (county.startsWith('escambia') || county.startsWith('santa rosa')) return 3;  // NW Florida
  if (county.startsWith('mobile')) return 4;          // Mobile County
  return 5;                                            // everywhere else
}

function sortByMarket(rows) {
  return rows.slice().sort((a, b) => {
    const r = marketRank(a) - marketRank(b);
    if (r !== 0) return r;
    return new Date(b.ModificationTimestamp || 0) - new Date(a.ModificationTimestamp || 0);
  });
}

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

// Server-side search. Sends the filters to Bridge so results cover all ~3,800
// active listings instead of only the batch we cache for the homepage.
// Diagnostic: what does this dataset actually put in CountyOrParish / City?
app.get('/api/mls-fields', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN, dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) return res.status(503).json({ error: 'MLS not configured.' });
  try {
    const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
      + `?access_token=${encodeURIComponent(token)}&$top=200`
      + `&$filter=${encodeURIComponent(STATUS_CLAUSE)}`;
    const r = await fetch(url);
    const json = await r.json();
    const rows = json.value || [];
    const tally = (f) => {
      const m = {};
      rows.forEach(x => { const v = x[f]; if (v !== undefined && v !== null && v !== '') m[v] = (m[v]||0)+1; });
      return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0, 40);
    };
    res.json({
      sampled: rows.length,
      hasCountyField: rows.length ? ('CountyOrParish' in rows[0]) : null,
      propertyTypes: tally('PropertyType'),
      propertySubTypes: tally('PropertySubType'),
      counties: tally('CountyOrParish'),
      cities: tally('City'),
      states: tally('StateOrProvince'),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/search', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN;
  const dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) return res.status(503).json({ error: 'MLS not configured.' });

  const q = req.query || {};
  const esc = v => String(v).replace(/'/g, "''");
  const num = v => { const n = parseInt(String(v || '').replace(/[^0-9]/g, ''), 10); return isNaN(n) ? null : n; };

  const parts = [];
  const status = (q.status || '').trim();
  if (status) {
    parts.push(`StandardStatus eq '${esc(status)}'`);
  } else {
    parts.push(ACTIVE_ONLY);   // default to what's genuinely for sale
  }
  if (q.city && q.city.trim()) {
    const c = esc(q.city.trim());
    // match the city OR anywhere in the street address, same as the old client-side behavior
    parts.push(`(contains(City,'${c}') or contains(UnparsedAddress,'${c}'))`);
  }
  // property type — the feed uses Residential, Land, Commercial Sale, Commercial Lease
  const ptype = String(q.ptype || '').trim();
  if (ptype === 'lease') {
    parts.push(`(PropertyType eq 'Commercial Lease' or PropertyType eq 'Residential Lease')`);
  } else if (ptype === 'commercial') {
    parts.push(`(PropertyType eq 'Commercial Sale' or PropertyType eq 'Commercial Lease')`);
  } else if (ptype === 'land') {
    parts.push(`PropertyType eq 'Land'`);
  } else if (ptype === 'residential') {
    parts.push(`PropertyType eq 'Residential'`);
  }
  const beds = num(q.beds);   if (beds)  parts.push(`BedroomsTotal ge ${beds}`);
  const min  = num(q.min);    if (min)   parts.push(`ListPrice ge ${min}`);
  const max  = num(q.max);    if (max)   parts.push(`ListPrice le ${max}`);

  const top  = Math.min(num(q.top) || 24, 200);
  const skip = num(q.skip) || 0;

  const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
    + `?access_token=${encodeURIComponent(token)}`
    + `&$filter=${encodeURIComponent(parts.join(' and '))}`
    + `&$orderby=ModificationTimestamp desc`
    + `&$top=${top}&$skip=${skip}&$count=true`;

  try {
    const r = await fetch(url);
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      console.error(`[search] Bridge ${r.status}: ${text.slice(0, 300)}`);
      return res.status(502).json({ error: `MLS search error ${r.status}`, detail: text.slice(0, 300) });
    }
    const json = await r.json();
    const rows = json.value || [];
    // with no city specified, rank by market so the beach leads
    const ordered = (q.city && q.city.trim()) ? rows : sortByMarket(rows);
    res.json({
      value: ordered,
      total: json['@odata.count'] != null ? json['@odata.count'] : null,
      top, skip,
    });
  } catch (e) {
    console.error('[search] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Market statistics computed from our own live feed. These are Avani's numbers
// from Gulf Coast MLS data, not a republication of anyone else's report.
// Note: the feed carries Active and Pending only — no closed sales — so this is
// list-side inventory, not sold statistics.
const MARKET_CITIES = ['Gulf Shores','Orange Beach','Fairhope','Daphne','Foley',
                       'Spanish Fort','Robertsdale','Bay Minette','Elberta','Summerdale'];
let marketCache = { data: null, at: 0 };

function median(nums) {
  if (!nums.length) return 0;
  const a = nums.slice().sort((x, y) => x - y);
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : Math.round((a[m - 1] + a[m]) / 2);
}

app.get('/api/market-stats', async (req, res) => {
  const token = process.env.BRIDGE_SERVER_TOKEN, dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) return res.status(503).json({ error: 'MLS not configured.' });

  if (marketCache.data && Date.now() - marketCache.at < 30 * 60 * 1000 && !req.query.fresh) {
    return res.json({ ...marketCache.data, cached: true });
  }

  try {
    // pull the Baldwin market in bulk, then compute locally
    const rows = [];
    const PAGE = 200;
    for (let skip = 0; skip < 1200; skip += PAGE) {
      const filter = ACTIVE_ONLY + " and contains(CountyOrParish,'Baldwin')";
      const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
        + `?access_token=${encodeURIComponent(token)}`
        + `&$filter=${encodeURIComponent(filter)}`
        + `&$orderby=ModificationTimestamp desc&$top=${PAGE}&$skip=${skip}`;
      const r = await fetch(url);
      if (!r.ok) break;
      const j = await r.json();
      const v = j.value || [];
      rows.push(...v);
      if (v.length < PAGE) break;
    }

    const now = Date.now();
    const daysAgo = iso => iso ? (now - new Date(iso).getTime()) / 86400000 : 9999;
    const priced = rows.filter(r => Number(r.ListPrice) > 0);

    const statsFor = subset => {
      const prices = subset.map(r => Number(r.ListPrice)).filter(Boolean);
      const ppsf = subset
        .filter(r => Number(r.LivingArea) > 250 && Number(r.ListPrice) > 0)
        .map(r => Number(r.ListPrice) / Number(r.LivingArea));
      return {
        count: subset.length,
        median: median(prices),
        average: prices.length ? Math.round(prices.reduce((a, b) => a + b, 0) / prices.length) : 0,
        low: prices.length ? Math.min(...prices) : 0,
        high: prices.length ? Math.max(...prices) : 0,
        pricePerSqft: ppsf.length ? Math.round(median(ppsf)) : 0,
        new7: subset.filter(r => daysAgo(r.OnMarketDate || r.ModificationTimestamp) <= 7).length,
        new30: subset.filter(r => daysAgo(r.OnMarketDate || r.ModificationTimestamp) <= 30).length,
      };
    };

    const byCity = {};
    MARKET_CITIES.forEach(c => {
      const subset = priced.filter(r => String(r.City || '').toLowerCase() === c.toLowerCase());
      if (subset.length) byCity[c] = statsFor(subset);
    });

    const byType = {};
    ['Residential', 'Land', 'Commercial Sale'].forEach(t => {
      const subset = priced.filter(r => r.PropertyType === t);
      if (subset.length) byType[t] = { count: subset.length, median: median(subset.map(r => Number(r.ListPrice))) };
    });

    const payload = {
      ok: true,
      generatedAt: new Date().toISOString(),
      area: 'Baldwin County, Alabama',
      source: 'Gulf Coast MLS \u2014 Mobile Area Association of REALTORS\u00AE',
      basis: 'Active listings only. Sold data is not included in this feed.',
      overall: statsFor(priced),
      byCity,
      byType,
    };
    marketCache = { data: payload, at: Date.now() };
    console.log(`[market-stats] ${priced.length} active Baldwin listings, median ${payload.overall.median}`);
    res.json(payload);
  } catch (e) {
    console.error('[market-stats] FAILED:', e.message);
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
    const seen = new Set();

    const fetchPage = async (filter, skip, wantCount) => {
      const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
        + `?access_token=${encodeURIComponent(token)}`
        + `&$filter=${encodeURIComponent(filter)}`
        + `&$orderby=ModificationTimestamp desc`
        + `&$top=${PAGE}&$skip=${skip}`
        + (wantCount ? '&$count=true' : '');
      const r = await fetch(url);
      if (!r.ok) {
        const text = await r.text().catch(() => '');
        throw Object.assign(new Error(`MLS API error ${r.status}`), { detail: text.slice(0, 400), status: r.status });
      }
      return r.json();
    };

    const collect = (rows) => {
      for (const row of rows) {
        const k = row.ListingKey || row.ListingId;
        if (k && !seen.has(k)) { seen.add(k); all.push(row); }
      }
    };

    try {
      // 1. Baldwin County first — this is the market the site is built around
      const baldwinFilter = ACTIVE_ONLY + " and contains(CountyOrParish,'Baldwin')";
      for (let skip = 0; skip < 400; skip += PAGE) {
        const json = await fetchPage(baldwinFilter, skip, false);
        const rows = json.value || [];
        collect(rows);
        if (rows.length < PAGE) break;
      }
      console.log(`[listings] Baldwin County: ${all.length}`);
    } catch (e) {
      console.warn('[listings] Baldwin-first query failed, falling back:', e.message);
    }

    // 2. Top up with the rest of the feed
    for (let skip = 0; skip < WANT; skip += PAGE) {
      let json;
      try {
        json = await fetchPage(ACTIVE_ONLY, skip, skip === 0);
      } catch (e) {
        if (all.length) break;
        return res.status(502).json({ error: e.message, detail: e.detail });
      }
      if (skip === 0 && json['@odata.count'] != null) totalAvailable = json['@odata.count'];
      const rows = json.value || [];
      collect(rows);
      if (rows.length < PAGE) break;
    }

    const ordered = sortByMarket(all);
    listingsCache = { data: ordered, at: Date.now(), totalAvailable };
    const beach = ordered.filter(r => marketRank(r) === 0).length;
    const baldwin = ordered.filter(r => marketRank(r) <= 2).length;
    console.log(`[listings] ${ordered.length} of ${totalAvailable == null ? '?' : totalAvailable} active \u2014 ${beach} beach, ${baldwin} Baldwin, sorted market-first`);
    res.json({ value: ordered, count: ordered.length, totalAvailable, beach, baldwin, cached: false });
  } catch (e) {
    console.error('[listings] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- MLS photo proxy ----------
   Flyers are drawn on a canvas and then exported. A listing photo loaded straight
   from the MLS CDN is cross-origin, which taints the canvas and makes toDataURL
   throw — so the image has to come back through our own origin.

   Restricted to the hosts the feed actually uses. An open proxy here would let
   anyone use this server to fetch arbitrary URLs, so unknown hosts are refused
   and logged rather than allowed through. */
const PHOTO_HOSTS = [
  'sparkplatform.com', 'bridgedataoutput.com', 'amazonaws.com',
  'cloudfront.net', 'mlsgrid.com', 'akamaized.net',
];

app.get('/api/listing-photo', async (req, res) => {
  const raw = String(req.query.u || '');
  let url;
  try { url = new URL(raw); } catch (e) { return res.status(400).json({ error: 'Bad URL.' }); }
  if (url.protocol !== 'https:') return res.status(400).json({ error: 'https only.' });
  const host = url.hostname.toLowerCase();
  const ok = PHOTO_HOSTS.some(h => host === h || host.endsWith('.' + h));
  if (!ok) {
    console.warn(`[photo proxy] refused host ${host} — add it to PHOTO_HOSTS if the feed uses it`);
    return res.status(403).json({ error: 'That image host is not allowed.' });
  }
  try {
    const r = await fetch(url.toString());
    if (!r.ok) return res.status(502).json({ error: `Upstream ${r.status}` });
    const type = r.headers.get('content-type') || '';
    if (!type.startsWith('image/')) return res.status(415).json({ error: 'Not an image.' });
    const buf = Buffer.from(await r.arrayBuffer());
    res.set('Content-Type', type);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('Access-Control-Allow-Origin', '*');
    res.send(buf);
  } catch (e) {
    console.error('[photo proxy] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Email notifications (via Resend's HTTP API) ----------
// Switched from direct Gmail SMTP to Resend after discovering this hosting
// platform blocks outbound SMTP entirely (ports 465 and 587 both refused
// the connection). Resend sends over regular HTTPS instead, which works
// fine here — same as our Supabase and Anthropic API calls.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = `${BROKERAGE_NAME} <notify@mail.bamacoast.com>`;
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
    const token = await createClientSession(id);
    res.json({ ok: true, token, client: { id, name, email: normalizedEmail, favorites: [], savedSearches: [] } });

    // Welcome email — sent after responding so a mail hiccup can never block signup.
    if (mailer) {
      const first = String(name || '').trim().split(/\s+/)[0] || 'there';
      mailer.sendMail({
        to: normalizedEmail,
        subject: `Welcome to ${BROKERAGE_NAME}`,
        text: `Hi ${first},

Thanks for creating an account at bamacoast.com.

You can now:
  - Save homes to your favorites
  - Save searches and pick up where you left off
  - Browse the full Gulf Coast MLS

Just click "Client Login" at the top of the site any time.

If you'd like help from a real person, call or text us at ${BROKERAGE_PHONE}.

Welcome aboard,
${BROKERAGE_NAME}
${BROKERAGE_PHONE}
bamacoast.com`,
      })
      .then(() => console.log(`[client welcome email] sent to ${normalizedEmail}`))
      .catch(e => console.error(`[client welcome email] FAILED for ${normalizedEmail}:`, e.message));
    } else {
      console.warn('[client welcome email] SKIPPED — mailer not configured.');
    }
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
    const token = await createClientSession(data.id);
    res.json({ ok: true, token, client: clientPublic(data) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/client/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  if (!(await requireClientSelf(req, res, req.params.id))) return;
  const { data, error } = await supabase.from('clients').select('*').eq('id', req.params.id).maybeSingle();
  if (error || !data) return res.status(404).json({ error: 'Account not found.' });
  res.json({ ok: true, client: clientPublic(data) });
});

app.post('/api/client/:id/favorites', async (req, res) => {
  if (!requireSupabase(res)) return;
  if (!(await requireClientSelf(req, res, req.params.id))) return;
  const { favorites } = req.body || {};
  const { error } = await supabase.from('clients').update({ favorites: favorites || [] }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post('/api/client/:id/saved-searches', async (req, res) => {
  if (!requireSupabase(res)) return;
  if (!(await requireClientSelf(req, res, req.params.id))) return;
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
    const sess = await createSession({ id, name, role: 'broker' });
    res.json({ ok: true, agent: { id, name, email: normalizedEmail, phone: '', role: 'broker' }, token: sess.token, expiresAt: sess.expiresAt });
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
          subject: `Reset your ${BROKERAGE_NAME} CRM password`,
          text: `Hi ${data.name},\n\nSomeone requested a password reset for your ${BROKERAGE_NAME} CRM account. If this was you, set a new password here (link expires in 1 hour):\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email.`,
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

app.post('/api/agent/logout', async (req, res) => {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (token) { try { await supabase.from('kv_store').delete().eq('key', 'session:' + token); } catch (e) {} }
  res.json({ ok: true });
});

app.get('/api/session', async (req, res) => {
  const sess = await getSession(req);
  if (!sess) return res.status(401).json({ error: 'No session.' });
  res.json({ ok: true, agentId: sess.agentId, role: sess.role, name: sess.name, expiresAt: sess.expiresAt });
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
    const sess = await createSession(data);
    res.json({ ok: true, agent: agentPublic(data), token: sess.token, expiresAt: sess.expiresAt });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// The qualifying broker must always be able to get in. Locking or deleting that
// account would leave the brokerage with no way to administer the CRM, so it's
// refused at the server rather than only hidden in the interface.
// Roles: broker (one owner) > admin (full CRM, restricted around the broker) > agent.
function normalizeRole(r) {
  const v = String(r || '').toLowerCase();
  if (v === 'broker') return 'broker';
  if (v === 'admin') return 'admin';
  return 'agent';
}

/* ---------- admin approval + bypass ----------
   An admin can do everything except touch the broker's own account. To do that
   they either request approval, or use a bypass code the broker has issued. */
async function getSetting(key) {
  if (!supabase) return null;
  try {
    const { data } = await supabase.from('kv_store').select('value').eq('key', key).maybeSingle();
    return data ? data.value : null;
  } catch (e) { return null; }
}
async function setSetting(key, value) {
  if (!supabase) return false;
  try {
    await supabase.from('kv_store').upsert({ key, value }, { onConflict: 'key' });
    return true;
  } catch (e) { return false; }
}

async function bypassCodeValid(code) {
  if (!code) return false;
  const rec = await getSetting('settings:adminBypass');
  if (!rec || !rec.code) return false;
  if (String(rec.code) !== String(code).trim()) return false;
  if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) return false;
  if (rec.singleUse && rec.usedAt) return false;
  if (rec.singleUse) {
    rec.usedAt = new Date().toISOString();
    await setSetting('settings:adminBypass', rec);
  }
  return true;
}

async function isBrokerAccount(id) {
  if (!supabase || !id) return false;
  try {
    const { data } = await supabase.from('agents').select('role').eq('id', id).maybeSingle();
    return !!(data && data.role === 'broker');
  } catch (e) { return false; }
}

// Broker issues a bypass code for an admin.
app.post('/api/admin/bypass', async (req, res) => {
  // Only the qualifying broker may issue a code — an admin issuing their own
  // would defeat the protection entirely.
  {const sess = await getSession(req);
   if (!sess || sess.role !== 'broker') return res.status(403).json({ error: 'Only the broker can issue a bypass code.' });}
  const { hours, singleUse } = req.body || {};
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const rec = {
    code,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + (Number(hours) || 24) * 3600 * 1000).toISOString(),
    singleUse: singleUse !== false,
    usedAt: null,
  };
  const ok = await setSetting('settings:adminBypass', rec);
  if (!ok) return res.status(500).json({ error: 'Could not save the code.' });
  res.json({ ok: true, code, expiresAt: rec.expiresAt, singleUse: rec.singleUse });
});

app.post('/api/admin/bypass/revoke', async (req, res) => {
  {const sess = await getSession(req);
   if (!sess || sess.role !== 'broker') return res.status(403).json({ error: 'Only the broker can revoke a bypass code.' });}
  await setSetting('settings:adminBypass', { code: null, revokedAt: new Date().toISOString() });
  res.json({ ok: true });
});

app.post('/api/admin/bypass/check', async (req, res) => {
  const ok = await bypassCodeValid((req.body || {}).code);
  res.json({ ok });
});

app.post('/api/agent/:id/set-active', async (req, res) => {
  {const sess = await getSession(req);
   if (!isStaff(sess)) {
     console.warn(`[security] unauthenticated attempt to lock/unlock agent ${req.params.id}`);
     return res.status(403).json({ error: 'Not permitted.' });
   }}
  if (!requireSupabase(res)) return;
  const { active } = req.body || {};
  if (!active && await isBrokerAccount(req.params.id)) {
    if (!(await bypassCodeValid((req.body || {}).bypassCode))) {
      console.warn(`[security] refused attempt to lock broker account ${req.params.id}`);
      return res.status(403).json({ error: "The broker account is protected. Request approval or use a bypass code." });
    }
    console.warn(`[security] broker account ${req.params.id} locked using a bypass code`);
  }
  try {
    const { error } = await supabase.from('agents').update({ active: !!active }).eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/:id/review-link', async (req, res) => {
  {const sess = await requireSession(req, res); if (!sess) return;
   if (sess.agentId !== req.params.id && !isStaff(sess)) {
     return res.status(403).json({ error: 'You can only set your own review link.' });
   }}
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
  // The sign-in screen calls this before anyone is logged in (to tell first-run
  // setup from a normal login), and public lead capture uses it to find the
  // broker. So it stays reachable — but contact details are staff-only.
  const sess = await getSession(req);
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase.from('agents').select('id,name,email,phone,role,review_link,active,last_login,created_at').order('name');
    if (error) return res.status(500).json({ error: error.message });
    const rows = data || [];
    if (!isStaff(sess)) {
      // names and roles only — no email, phone, or login history
      return res.json({
        ok: true,
        agents: rows.map(a => ({ id: a.id, name: a.name, role: a.role, active: a.active !== false })),
        limited: true,
      });
    }
    res.json({ ok: true, agents: rows.map(agentPublic) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agent/create', async (req, res) => {
  {const sess = await getSession(req); if (!isStaff(sess)) return res.status(403).json({ error: 'Not permitted.' });}
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
    const { error } = await supabase.from('agents').insert({ id, name, email: normalizedEmail, password_hash, phone: phone || '', role: normalizeRole(role) });
    if (error) return res.status(500).json({ error: error.message });
    let emailStatus = 'skipped';
    if (mailer) {
      const loginUrl = `${req.protocol}://${req.get('host')}/`;
      try {
        await mailer.sendMail({
          to: normalizedEmail,
          subject: `Your ${BROKERAGE_NAME} CRM login`,
          text: `Hi ${name},\n\nYou've been added to the ${BROKERAGE_NAME} CRM. Here's how to log in:\n\n${loginUrl}\nClick "Agent Login"\n\nUsername (email): ${normalizedEmail}\nTemporary password: ${defaultPassword}\n\nOnce you're in, we recommend changing your password to something only you know — you'll find that option once logged in.\n\nWelcome aboard,\n${BROKERAGE_NAME}`,
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
    res.json({ ok: true, agent: { id, name, email: normalizedEmail, phone: phone || '', role: normalizeRole(role) }, emailStatus });
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
  {const sess = await getSession(req);
   if (!isStaff(sess)) {
     console.warn(`[security] unauthenticated password-reset attempt on agent ${req.params.id}`);
     return res.status(403).json({ error: 'Not permitted.' });
   }
   // an admin must not be able to reset the broker's password and take the account
   if (sess.role !== 'broker' && await isBrokerAccount(req.params.id)) {
     if (!(await bypassCodeValid((req.body || {}).bypassCode))) {
       console.warn(`[security] admin ${sess.agentId} blocked resetting the broker password`);
       return res.status(403).json({ error: 'The broker account is protected. Request approval or use a bypass code.' });
     }
   }}
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
          subject: `Your ${BROKERAGE_NAME} CRM password was reset`,
          text: `Hi ${data.name},\n\nYour CRM password was reset by your broker. Your temporary password is: ${defaultPassword}\n\nPlease log in and change it to something only you know.\n\n${BROKERAGE_NAME}`,
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

// Edit an agent's account: name, email, phone, role. Staff only, and the
// broker's own record stays untouchable without a bypass code.
app.patch('/api/agent/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await getSession(req);
  if (!isStaff(sess)) return res.status(403).json({ error: 'Not permitted.' });

  const id = req.params.id;
  const { name, email, phone, role } = req.body || {};

  if (await isBrokerAccount(id) && sess.role !== 'broker') {
    if (!(await bypassCodeValid((req.body || {}).bypassCode))) {
      return res.status(403).json({ error: 'The broker account is protected. Request approval or use a bypass code.' });
    }
  }
  // only the broker may hand out broker or admin rights
  if (role && sess.role !== 'broker' && normalizeRole(role) !== 'agent') {
    return res.status(403).json({ error: 'Only the broker can grant admin or broker access.' });
  }

  const patch = {};
  if (typeof name === 'string' && name.trim()) patch.name = name.trim();
  if (typeof phone === 'string') patch.phone = phone.trim();
  if (typeof email === 'string' && email.trim()) {
    const normalized = email.trim().toLowerCase();
    const { data: clash } = await supabase.from('agents').select('id').eq('email', normalized).maybeSingle();
    if (clash && clash.id !== id) return res.status(409).json({ error: 'Another account already uses that email.' });
    patch.email = normalized;
  }
  if (role) patch.role = normalizeRole(role);
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nothing to update.' });

  try {
    const { error } = await supabase.from('agents').update(patch).eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    console.log(`[agent update] ${sess.name} updated ${id}: ${Object.keys(patch).join(', ')}`);
    res.json({ ok: true, updated: Object.keys(patch) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/agent/:id', async (req, res) => {
  {const sess = await getSession(req);
   if (!isStaff(sess)) {
     console.warn(`[security] unauthenticated attempt to delete agent ${req.params.id}`);
     return res.status(403).json({ error: 'Not permitted.' });
   }}
  if (await isBrokerAccount(req.params.id)) {
    if (!(await bypassCodeValid((req.query || {}).bypassCode))) {
      console.warn(`[security] refused attempt to delete broker account ${req.params.id}`);
      return res.status(403).json({ error: "The broker account is protected. Request approval or use a bypass code." });
    }
    console.warn(`[security] broker account ${req.params.id} deleted using a bypass code`);
  }
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

// Each agent chooses how they hear about their leads.
app.get('/api/agent/:id/alerts', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.agentId !== req.params.id && !isStaff(sess)) return res.status(403).json({ error: 'Not permitted.' });
  const p = await getSetting('agentAlerts:' + req.params.id) || {};
  res.json({ ok: true, emailAlerts: p.emailAlerts !== false, smsAddress: p.smsAddress || '' });
});

app.post('/api/agent/:id/alerts', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.agentId !== req.params.id && !isStaff(sess)) return res.status(403).json({ error: 'Not permitted.' });
  const b = req.body || {};
  await setSetting('agentAlerts:' + req.params.id, {
    emailAlerts: b.emailAlerts !== false,
    smsAddress: String(b.smsAddress || '').trim().slice(0, 120),
  });
  res.json({ ok: true });
});

// Agent-to-agent lead transfer. Agents cover for each other — out of office,
// wrong end of the county — and the receiving agent should get it as if it
// just came in, knowing who passed it over.
app.post('/api/lead/transfer', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role === 'admin') return res.status(403).json({ error: 'Admin accounts do not handle leads.' });
  const { toAgentId, lead, note } = req.body || {};
  if (!toAgentId || !lead) return res.status(400).json({ error: 'Missing details.' });

  // an agent may only pass on a lead that is actually theirs
  if (!isStaff(sess) && lead.assignedAgentId && lead.assignedAgentId !== sess.agentId) {
    return res.status(403).json({ error: "That lead isn't assigned to you." });
  }
  if (!mailer) return res.json({ ok: true, emailed: false });

  try {
    const { data: to } = await supabase.from('agents')
      .select('id,name,email,active').eq('id', toAgentId).maybeSingle();
    if (!to) return res.status(404).json({ error: 'Agent not found.' });
    if (to.active === false) return res.status(400).json({ error: 'That agent is locked out.' });

    const L = lead;
    const from = sess.name || 'A colleague';
    await mailer.sendMail({
      to: to.email,
      subject: `${from} passed you a lead: ${L.name || 'Unknown'}`,
      text: `${from} has handed this lead to you.

${note ? 'Their note: ' + note + '\n\n' : ''}Name:  ${L.name || '(not provided)'}
Email: ${L.email || '(not provided)'}
Phone: ${L.phone || '(not provided)'}
Source: ${L.source || 'website'}
${L.listingLabel ? 'Listing: ' + L.listingLabel + '\n' : ''}
What they said:
${L.message || '(nothing)'}

It's yours now — log in at bamacoast.com to work it.`,
    });

    const prof = await getSetting('agentAlerts:' + to.id) || {};
    if (prof.smsAddress) {
      try {
        await mailer.sendMail({
          to: prof.smsAddress,
          subject: 'New lead',
          text: `${from} passed you a lead: ${L.name || 'Unknown'} ${L.phone || L.email || ''}`.slice(0, 150),
        });
      } catch (e) { console.warn('[transfer] sms copy failed:', e.message); }
    }
    console.log(`[lead transfer] ${from} -> ${to.name} (${L.name || 'unknown'})`);
    res.json({ ok: true, emailed: true, toName: to.name });
  } catch (e) {
    console.error('[lead transfer] FAILED:', e.message);
    res.status(500).json({ error: e.message });
  }
});

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

    // The assigned agent gets their own copy — a lead sitting only in the
    // broker's inbox is a lead nobody is calling.
    const assignedId = (req.body || {}).assignedAgentId;
    if (assignedId) {
      try {
        const { data: ag } = await supabase.from('agents')
          .select('id,name,email,active').eq('id', assignedId).maybeSingle();
        if (ag && ag.email && ag.active !== false && ag.email !== notifyTo) {
          const prof = await getSetting('agentAlerts:' + ag.id) || {};
          if (prof.emailAlerts !== false) {
            if (prof.smsAddress) {
              // Carrier email-to-text gateways drop long or formatted messages,
              // so this one is deliberately short and plain.
              try {
                await mailer.sendMail({
                  to: prof.smsAddress,
                  subject: 'New lead',
                  text: `${name || 'New lead'} ${phone || email || ''} - ${source || 'website'}`.slice(0, 140),
                });
                console.log(`[lead notification] text sent to ${prof.smsAddress}`);
              } catch (e) {
                console.warn(`[lead notification] text FAILED to ${prof.smsAddress}: ${e.message}`);
              }
            }
            const extra = [ag.email];
            for (const to of extra) {
              await mailer.sendMail({
                to,
                subject: `New lead: ${name || 'Unknown'}`,
                text: `${name || 'Someone'} just inquired through bamacoast.com.

Name:  ${name || '(not provided)'}
Email: ${email || '(not provided)'}
Phone: ${phone || '(not provided)'}
Source: ${source || 'website'}
${listingLabel ? 'Listing: ' + listingLabel + '\n' : ''}
Message:
${message || '(none)'}

Call them before someone else does.
bamacoast.com`,
              });
            }
            console.log(`[lead notification] agent copy sent to ${extra.join(', ')}`);
          }
        }
      } catch (e) {
        console.error('[lead notification] agent copy FAILED:', e.message);
      }
    }
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

const CHAT_SYSTEM_PROMPT = `You are a friendly, helpful assistant for ${BROKERAGE_NAME}, a boutique brokerage licensed in Alabama and Florida, serving Baldwin and Mobile County, Alabama (Gulf Shores, Orange Beach, Fairhope, Foley, Daphne, Mobile) and the Perdido Key and Pensacola corridor in Florida. Broker: Jimmy Thies, phone ${BROKERAGE_PHONE}.

Always refer to the brokerage by its full name, "${BROKERAGE_NAME}" — never an abbreviation. Alabama license law requires the company name to appear as licensed.

Your main goal is to get the visitor's NAME and EMAIL (or phone) early, then gather the details a real agent would need. Ask ONE question at a time, in natural conversation.

GETTING CONTACT INFO — this is your top priority:
After you have answered their first question helpfully, ask for their first name. Once you have a name, use it, and within the next reply or two ask for the best email or phone number to reach them — frame it as a benefit, not a form. Good phrasings: "What's the best email for you? I'll have Jimmy send over some options that fit." or "Happy to have Jimmy follow up with specifics — what's the best number to reach you?"

Do NOT wait until you have fully qualified them before asking. Aim to have name and contact info within the first 2-3 exchanges, then keep qualifying naturally afterward.

If they decline or dodge, that's completely fine — never pressure them, never ask twice in a row, and keep helping regardless. Ask again later only if the conversation naturally opens the door.

If they seem to be BUYING: find out their general timeline (just looking / next few months / ready now), and whether they're pre-approved for financing yet (or paying cash). Don't ask both at once — work it into the conversation naturally.

If they seem to be SELLING: ask for the property address (or at least the city/area), what they think it might be worth or what prompted them to consider selling, their rough timeline, and whether there's anything unusual about the situation (inherited property, needs repairs, relocation deadline, etc.).

If they're unsure what they want, or their answers are vague, gently suggest: "Would it help to just send a quick message to Jimmy directly? He can set up a time to talk through it." and encourage them to use the "leave your contact info" option.

The site shows live MLS listings from Gulf Coast MLS, so visitors can search real inventory themselves. You cannot see those listings from this conversation, so never quote a specific price, address, or availability — point them to the search on the site instead, or offer to have an agent pull exactly what they need.

Never state who pays commission or say representation is free. Commissions are negotiable, are not set by law, and are covered in a written buyer agreement signed before touring. If asked how agents are paid, say exactly that and offer to connect them with Jimmy.

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
      text: `Hi ${toName || 'there'},\n\nThank you so much for working with ${agentName || BROKERAGE_NAME}! If you have a minute, we'd really appreciate a quick review — it helps other buyers and sellers in the area find us.\n\n${reviewLink ? `Leave a Google review: ${reviewLink}\n\n` : ''}Or leave a review directly on our site: ${siteReviewUrl}\n\nThank you again,\nJimmy Thies\n${BROKERAGE_NAME}`,
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
    const prompt = `Draft a warm, professional, concise reply (as Jimmy Thies, Broker/Owner of ${BROKERAGE_NAME}) to a lead named "${name || 'there'}" who submitted this via the website (source: ${source || 'website'}${listingLabel ? ', re: ' + listingLabel : ''}):\n\n"${message || '(no message provided)'}"\n\nKeep it to 3-5 sentences. Sign off as Jimmy. Do not include a subject line, just the message body.`;
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
// The live secret is BRIDGE_SERVER_TOKEN. This read BRIDGE_TOKEN, which is not
// set on this deployment, so /api/mls-test always failed with "not set".
const BRIDGE_TOKEN   = process.env.BRIDGE_SERVER_TOKEN || process.env.BRIDGE_TOKEN;
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
    serverVersion: 'v56',
    routes: ['market-stats','mls-fields','search','listings'],
    brokerage: BROKERAGE_NAME,
    database: !!supabase,
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

  // Social platforms render og:title large and bold and og:description in small
  // grey text. With the brokerage name only in the description it was displayed
  // smaller than every other element of the card, which is the opposite of what
  // AREC 790-X-3-.16 requires. It leads the title now.
  const title = `${BROKERAGE_NAME} — ${listing.UnparsedAddress}, ${listing.City} · $${listing.ListPrice.toLocaleString()}`;
  const desc = `${listing.BedroomsTotal} bd · ${listing.BathroomsTotalInteger} ba · ${listing.LivingArea.toLocaleString()} sqft`;
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

// ---------- agent profile pages ----------
// Clean URLs like /christinathies. These have to work when someone lands on
// them directly from a business card or a text — not only via a click.
/* ---------- license compliance ----------
   An agent's public page must never imply they can practice where they aren't
   licensed. This is the broker's exposure, so it is enforced server-side and
   the wording is generated from the license record rather than typed freely. */
const STATE_NAMES = { AL: 'Alabama', FL: 'Florida' };

// Words that imply practicing in a given state.
const STATE_TERMS = {
  FL: ['florida', ' fl ', 'perdido key', 'pensacola', 'escambia', 'santa rosa',
       'gulf breeze', 'navarre', 'innerarity', 'panhandle'],
  AL: ['alabama', ' al ', 'baldwin', 'mobile county', 'gulf shores', 'orange beach',
       'fairhope', 'daphne', 'foley', 'fort morgan', 'ono island'],
};

function licensedStatesOf(profile) {
  const list = Array.isArray(profile && profile.licensedStates) ? profile.licensedStates : [];
  return list.filter(x => STATE_NAMES[x]);
}

/* Returns the states a piece of text implies, that the agent isn't licensed in. */
function unlicensedClaims(text, licensed) {
  const t = ' ' + String(text || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ') + ' ';
  const bad = [];
  Object.entries(STATE_TERMS).forEach(([code, terms]) => {
    if (licensed.includes(code)) return;
    const hit = terms.find(term => t.includes(term.trim().length <= 3 ? term : term.trim()));
    if (hit) bad.push({ state: code, name: STATE_NAMES[code], term: hit.trim() });
  });
  return bad;
}

/* The service-area sentence, built from the license record. */
function serviceAreaSentence(licensed) {
  const parts = [];
  if (licensed.includes('AL')) parts.push('Baldwin and Mobile County, Alabama');
  if (licensed.includes('FL')) parts.push('the Perdido Key and Pensacola corridor in Florida');
  if (!parts.length) return '';
  return parts.join(' and ');
}

/* AREC Rule 790-X-3-.16, Advertising Teams: a team name must include "team" or
   "group", and must not use terms suggesting it is a real estate company in its
   own right. The title field is free text, so an agent can otherwise publish
   "Coastal Properties LLC" and it goes straight to a public page. */
const COMPANY_TERMS = [
  'corporation', 'corp', 'incorporated', 'inc',
  'limited liability company', 'llc', 'l.l.c',
  'partnership', 'llp', 'lp',
  'company', 'co.', 'enterprise', 'enterprises', 'business',
  'realty', 'brokerage', 'real estate group inc',
];
const TEAM_WORDS = ['team', 'group'];

/* Returns a problem description, or null when the title is acceptable. */
function teamNameProblem(title) {
  const raw = String(title || '').trim();
  if (!raw) return null;
  const t = ' ' + raw.toLowerCase().replace(/[^a-z0-9. ]/g, ' ').replace(/\s+/g, ' ') + ' ';

  // The brokerage's own name is always fine — that is the required attribution.
  if (raw.toLowerCase().includes(BROKERAGE_NAME.toLowerCase())) return null;

  const hit = COMPANY_TERMS.find(term => t.includes(' ' + term + ' '));
  if (hit) {
    return `"${raw}" uses the word "${hit.trim()}", which suggests this is a separate real estate company. ` +
           `AREC does not permit team or title names that could lead the public to think a team is its own brokerage.`;
  }
  // If it reads like a named team, it has to say so.
  const looksLikeTeam = /\bthe\b/.test(t) || /\b(partners|associates|collective|realtors)\b/.test(t);
  if (looksLikeTeam && !TEAM_WORDS.some(w => t.includes(' ' + w + ' '))) {
    return `"${raw}" reads as a team name but does not include the word "team" or "group", which AREC requires.`;
  }
  return null;
}

function slugify(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/* Email a flyer as a real attachment. mailto: cannot attach a file, so the only
   honest way to "email this flyer" is to send it server-side. */
app.post('/api/marketing/email', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!mailer) return res.status(503).json({ error: 'Email is not configured.' });

  const { to, subject, message, filename, dataBase64, mimeType } = req.body || {};
  const recipients = String(to || '').split(/[,;]/).map(x => x.trim()).filter(Boolean);
  if (!recipients.length) return res.status(400).json({ error: 'Who should it go to?' });
  if (recipients.length > 10) return res.status(400).json({ error: 'Ten recipients at most.' });
  if (!dataBase64) return res.status(400).json({ error: 'Nothing attached.' });

  const bytes = Math.ceil(String(dataBase64).length * 3 / 4);
  if (bytes > 10 * 1024 * 1024) return res.status(413).json({ error: 'That file is too large to email.' });

  const safeName = String(filename || 'flyer.pdf').replace(/[^A-Za-z0-9._-]/g, '');
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: recipients,
        reply_to: sess.email || undefined,
        subject: String(subject || '').slice(0, 200) || 'A flyer from ' + BROKERAGE_NAME,
        text: (String(message || '').slice(0, 4000) || 'Attached.') +
              `\n\n\u2014 ${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\nbamacoast.com`,
        attachments: [{ filename: safeName, content: String(dataBase64), content_type: mimeType || 'application/pdf' }],
      }),
    });
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      console.error('[marketing email] Resend error:', r.status, t.slice(0, 200));
      return res.status(502).json({ error: 'The mail service refused it.' });
    }
    console.log(`[marketing] ${sess.name} emailed ${safeName} to ${recipients.length} recipient(s)`);
    res.json({ ok: true, sent: recipients.length });
  } catch (e) {
    console.error('[marketing email] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* A scan from a card or a rider lands on the agent's page carrying ?src= and an
   optional ?c= campaign tag. Recording it is what makes printed material
   measurable — otherwise there is no way to know which piece pulled. */
app.post('/api/marketing/scan', async (req, res) => {
  const b = req.body || {};
  const slug = String(b.slug || '').slice(0, 80).replace(/[^a-z0-9]/gi, '');
  const src  = String(b.src  || '').slice(0, 24).replace(/[^a-z0-9_-]/gi, '');
  const camp = String(b.campaign || '').slice(0, 40).replace(/[^a-z0-9_-]/gi, '');
  if (!slug || !src) return res.json({ ok: true, skipped: true });
  const day = new Date().toISOString().slice(0, 10);
  const key = 'marketingScans:' + slug;
  try {
    const rec = (await getSetting(key)) || { slug, total: 0, byDay: {}, bySrc: {}, byCampaign: {} };
    rec.total = (rec.total || 0) + 1;
    rec.byDay[day] = (rec.byDay[day] || 0) + 1;
    rec.bySrc[src] = (rec.bySrc[src] || 0) + 1;
    if (camp) rec.byCampaign[camp] = (rec.byCampaign[camp] || 0) + 1;
    rec.lastAt = new Date().toISOString();
    await setSetting(key, rec);
    console.log(`[marketing] scan ${slug} src=${src}${camp ? ' c=' + camp : ''}`);
  } catch (e) { console.warn('[marketing] scan record failed:', e.message); }
  res.json({ ok: true });
});

app.get('/api/marketing/scans/:slug', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const slug = String(req.params.slug || '').replace(/[^a-z0-9]/gi, '');
  // an agent sees their own numbers; staff see anyone's
  if (!isStaff(sess) && slugify(sess.name || '') !== slug) {
    return res.status(403).json({ error: 'Not permitted.' });
  }
  const rec = (await getSetting('marketingScans:' + slug)) || { slug, total: 0, byDay: {}, bySrc: {}, byCampaign: {} };
  res.json({ ok: true, scans: rec });
});

app.get('/api/agent/by-slug/:slug', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data } = await supabase.from('agents')
      .select('id,name,email,phone,role,active').order('name');
    const match = (data || []).find(a => a.active !== false && slugify(a.name) === slugify(req.params.slug));
    if (!match) return res.status(404).json({ error: 'No agent by that name.' });
    const profile = await getSetting('agentPublic:' + match.id) || {};
    const publicPhone = profile.publicPhone || match.phone || '251-229-3216';
    const publicEmail = profile.publicEmail || match.email || '';
    res.json({ ok: true, agent: {
      id: match.id, name: match.name, email: publicEmail, phone: publicPhone,
      phoneIsBrokerage: !(profile.publicPhone || match.phone),
      role: match.role, slug: slugify(match.name),
      bio: profile.bio || '', photo: profile.photo || '', title: profile.title || '',
      specialties: profile.specialties || '', languages: profile.languages || '',
      facebook: profile.facebook || '', instagram: profile.instagram || '',
      licensedStates: licensedStatesOf(profile),
      licenseNumbers: profile.licenseNumbers || {},
      serviceArea: serviceAreaSentence(licensedStatesOf(profile)),
    }});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/agent/directory', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data } = await supabase.from('agents')
      .select('id,name,email,phone,role,active').order('name');
    const rows = (data || []).filter(a => a.active !== false);
    const out = [];
    for (const a of rows) {
      const p = await getSetting('agentPublic:' + a.id) || {};
      out.push({ id: a.id, name: a.name, email: p.publicEmail || a.email,
                 phone: p.publicPhone || a.phone || '251-229-3216', role: a.role,
                 slug: slugify(a.name), title: p.title || '', photo: p.photo || '',
                 licensedStates: licensedStatesOf(p),
                 bio: (p.bio || '').slice(0, 180) });
    }
    res.json({ ok: true, agents: out });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// An agent edits their own public profile; staff can edit anyone's.
app.post('/api/agent/:id/public-profile', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.agentId !== req.params.id && !isStaff(sess)) {
    return res.status(403).json({ error: 'You can only edit your own profile.' });
  }
  const b = req.body || {};
  const clean = v => String(v || '').slice(0, 4000);
  // photos arrive as a resized data URI — bigger allowance, still bounded
  const cleanPhoto = v => {
    const t = String(v || '');
    if (t.length > 900000) return '';
    if (t && !/^(https?:\/\/|data:image\/(jpeg|png|webp);base64,)/.test(t)) return '';
    return t;
  };

  // Only the broker or an admin sets which states an agent is licensed in —
  // an agent must not be able to grant themselves a licence.
  const existing = await getSetting('agentPublic:' + req.params.id) || {};
  const licensed = isStaff(sess)
    ? (Array.isArray(b.licensedStates) ? b.licensedStates.filter(x => STATE_NAMES[x]) : licensedStatesOf(existing))
    : licensedStatesOf(existing);

  const teamIssue = teamNameProblem(b.title);
  if (teamIssue) {
    console.warn(`[license] blocked profile for ${req.params.id}: team name — ${teamIssue}`);
    return res.status(422).json({ error: teamIssue, field: 'title' });
  }

  const claims = unlicensedClaims(
    [clean(b.bio), clean(b.title), clean(b.specialties)].join(' '), licensed);
  if (claims.length) {
    const c = claims[0];
    console.warn(`[license] blocked profile for ${req.params.id}: mentions ${c.term} without a ${c.name} licence`);
    return res.status(422).json({
      error: `This mentions "${c.term}" but there is no ${c.name} license on file for this agent. ` +
             `Remove the reference, or ask the broker to add the ${c.name} license first.`,
      state: c.state, term: c.term,
    });
  }

  const profile = {
    title: clean(b.title), bio: clean(b.bio), photo: cleanPhoto(b.photo),
    publicPhone: clean(b.publicPhone), publicEmail: clean(b.publicEmail),
    licensedStates: licensed,
    licenseNumbers: isStaff(sess) ? (b.licenseNumbers || existing.licenseNumbers || {})
                                  : (existing.licenseNumbers || {}),
    specialties: clean(b.specialties), languages: clean(b.languages),
    facebook: clean(b.facebook), instagram: clean(b.instagram),
    updatedAt: new Date().toISOString(),
  };
  const ok = await setSetting('agentPublic:' + req.params.id, profile);
  if (!ok) return res.status(500).json({ error: 'Could not save.' });
  res.json({ ok: true, profile });
});

// ---------- static site ----------
app.use(express.static(path.join(__dirname, 'public')));

// Anything that isn't a file or an API call is treated as an agent slug and
// handed to the app, which resolves it client-side.
app.get('/:slug', (req, res, next) => {
  const slug = req.params.slug || '';
  if (slug.startsWith('api') || slug.includes('.')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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
