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
/* CAN-SPAM requires a real postal address in every commercial email. This is not
   decoration — an email without it is a violation on its own. */
const BROKERAGE_ADDRESS = '191 Northshore Circle, Suite 100-D, Gulf Shores, AL 36542';
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
const PUBLIC_READ_KEYS = ['settings:viewLimit', 'settings:testimonials', 'settings:reviewLink',
                          'settings:exitIntent',    // wording for the leaving-the-site prompt
                          'settings:beachReel'];    // homepage photographs
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
  if (k.startsWith('session:') || k.startsWith('clientSession:')
      || k.startsWith('clientReset:')) return false;
  // HR records hold taxpayer IDs and go through their own routes only
  if (k.startsWith('agentHR:')) return false;
  // trackers go through their own routes; the token index must never be listable
  if (k.startsWith('trackerTok:')) return false;
  if (k.startsWith('ohTok:')) return false;
  if (k.startsWith('ssTok:')) return false;
  if (k.startsWith('savedSearch:')) return k.startsWith('savedSearch:' + sess.agentId + ':');
  if (k.startsWith('openHouse:')) return k.startsWith('openHouse:' + sess.agentId + ':');
  if (k.startsWith('tracker:')) return k.startsWith('tracker:' + sess.agentId + ':');
  // Anything not named above was previously readable by any signed-in agent —
  // including settings:leadArchive, the entire archived lead history. Shared
  // keys are now allowlisted, so a new key is private until it is listed.
  const AGENT_READABLE = new Set([
    'settings:viewLimit', 'settings:testimonials', 'settings:reviewLink',
    'settings:agentPlans', 'settings:agentPlanHistory', 'settings:closedDeals',
    'settings:expenses', 'settings:dealSubmissions', 'settings:officeCalendar',
    'settings:resourceLinks', 'settings:marketingPolicy', 'settings:exitIntent',
    'settings:beachReel',
  ]);
  if (k.startsWith('settings:')) return AGENT_READABLE.has(k) && !write;
  if (k.startsWith('lead:')) return true;                 // ownership checked separately
  if (k.startsWith('agentAlerts:')) return k === 'agentAlerts:' + sess.agentId;
  if (k.startsWith('agentPublic:')) return true;          // public profile data
  // personal CRM preferences — tab order and the like. Own record only: without
  // this the catch-all below would let any agent read or overwrite anyone else's.
  if (k.startsWith('crmPrefs:')) return k === 'crmPrefs:' + sess.agentId;
  // an agent's own diary. The office calendar is a settings key the broker writes
  // and everyone reads.
  if (k.startsWith('calendar:')) return k === 'calendar:' + sess.agentId;
  /* An agent's own record of their deals. Deliberately nothing to do with
     settings:closedDeals, which is the broker's ledger — keeping them apart means
     an agent can keep whatever notes they like without any risk of moving a
     number the brokerage counts. */
  if (k.startsWith('agentDeals:')) return k === 'agentDeals:' + sess.agentId;
  // personal task list, what has been ticked, and the end-of-day log
  if (k.startsWith('crmTasks:')) return k === 'crmTasks:' + sess.agentId;
  // each agent decides what reaches them, without asking the broker
  if (k.startsWith('notify:')) return k === 'notify:' + sess.agentId;
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
  if (String(req.params.key || '').match(/^(session|clientSession|clientReset|agentHR):/)) {
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
    if (prefix.startsWith('session:') || prefix.startsWith('clientSession:')
        || prefix.startsWith('clientReset:') || prefix.startsWith('agentHR:')
        || prefix.startsWith('trackerTok:') || prefix.startsWith('ohTok:')
        || prefix.startsWith('ssTok:')) {
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
/* Broadcasts go out from a separate subdomain so newsletter volume can never
   damage the reputation of the mail that HAS to arrive — password resets, review
   requests, transaction updates. Falls back to the transactional sender until
   news.bamacoast.com is verified in Resend, so nothing breaks in the meantime. */
const RESEND_MARKETING_FROM = process.env.RESEND_MARKETING_FROM
  || `${BROKERAGE_NAME} <news@news.bamacoast.com>`;
const MARKETING_READY = !!process.env.RESEND_MARKETING_FROM;
let mailer = null;
if (RESEND_API_KEY) {
  mailer = {
    sendMail: async ({ to, subject, text, marketing }) => {
      const from = marketing && MARKETING_READY ? RESEND_MARKETING_FROM : RESEND_FROM;
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ from, to, subject, text }),
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

/* ---------- agent HR records ----------
   Address, emergency contact, license dates, W-9 status and the taxpayer ID
   needed to produce a 1099. Everything the broker currently keeps asking agents
   to re-send.

   The TIN is the most sensitive thing in this system. It is encrypted at rest
   with AES-256-GCM and only ever leaves the server as last-four, except in the
   1099 worksheet, which the broker alone can generate. If HR_ENCRYPTION_KEY is
   not configured the server REFUSES to store a TIN rather than writing it in
   clear text — a missing environment variable must not quietly downgrade this.

   To generate the key:  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   then set HR_ENCRYPTION_KEY in the hosting environment variables.            */
const HR_KEY_HEX = process.env.HR_ENCRYPTION_KEY || '';
const HR_KEY = /^[0-9a-f]{64}$/i.test(HR_KEY_HEX) ? Buffer.from(HR_KEY_HEX, 'hex') : null;
if (!HR_KEY && HR_KEY_HEX) console.warn('[hr] HR_ENCRYPTION_KEY is set but is not 64 hex characters — ignoring it.');

function encryptTin(plain){
  if (!HR_KEY) throw new Error('HR_ENCRYPTION_KEY is not configured.');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', HR_KEY, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return [iv.toString('hex'), c.getAuthTag().toString('hex'), enc.toString('hex')].join(':');
}

function decryptTin(blob){
  if (!HR_KEY || !blob) return null;
  try {
    const [ivh, tagh, dh] = String(blob).split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', HR_KEY, Buffer.from(ivh, 'hex'));
    d.setAuthTag(Buffer.from(tagh, 'hex'));
    return Buffer.concat([d.update(Buffer.from(dh, 'hex')), d.final()]).toString('utf8');
  } catch (e) {
    console.error('[hr] TIN decrypt failed — wrong key, or the record was written under a different one');
    return null;
  }
}

const HR_FIELDS = ['legalName','entityName','address1','address2','city','state','zip',
                   'personalPhone','personalEmail','dob','startDate','endDate',
                   'emergencyName','emergencyPhone','emergencyRelation',
                   'licenseExpiry','w9OnFile','w9Date','tinType','notes',
                   // an agent's own accountant, so they can send their year-end
                   // documents themselves rather than asking the broker for them
                   'cpaEmail'];

/* What comes back to the browser: never the TIN itself, only the last four. */
function hrPublic(rec){
  const out = {};
  HR_FIELDS.forEach(f => { out[f] = (rec && rec[f]) || ''; });
  out.tinLast4 = (rec && rec.tinLast4) || '';
  out.tinOnFile = !!(rec && rec.tinEnc);
  out.updatedAt = (rec && rec.updatedAt) || '';
  return out;
}

/* ---------- one view of an agent's details ----------
   Two records held the same facts under different names: agentProfile, which the
   agent fills in on My details, and agentHR, which the broker keeps and which the
   1099 reads. An agent could complete every field and still be reported as
   "missing address, missing taxpayer ID" because nothing was copied across.

   Rather than making anybody type it twice, the HR record reads through to the
   profile wherever the broker has not entered something of their own. The broker's
   value always wins when there is one; the taxpayer ID stays HR-only because only
   the broker may enter it. */
const HR_FROM_PROFILE = {
  address1: 'address', city: 'city', state: 'state', zip: 'zip',
  personalPhone: 'phone', personalEmail: 'personalEmail',
  dob: 'dob', startDate: 'startDate',
  emergencyName: 'emergencyName', emergencyPhone: 'emergencyPhone',
  licenseExpiry: 'licenseExp',
};

async function mergedHR(agentId, agentName) {
  const hr = (await getSetting('agentHR:' + agentId)) || {};
  const profile = (await getSetting('agentProfile:' + agentId)) || {};
  const out = Object.assign({}, hr);

  for (const [hrKey, pKey] of Object.entries(HR_FROM_PROFILE)) {
    if (!String(out[hrKey] || '').trim() && String(profile[pKey] || '').trim()) {
      out[hrKey] = profile[pKey];
      out._fromProfile = true;
    }
  }
  // a legal name is required to file; the display name is a reasonable default
  if (!String(out.legalName || '').trim() && agentName) out.legalName = agentName;
  // the agent's own W-9 answer counts until the broker records otherwise
  if (out.w9OnFile === undefined && profile.w9) {
    out.w9OnFile = /^(y|yes|true|1|on file)/i.test(String(profile.w9).trim());
  }
  return out;
}

app.get('/api/agent/:id/hr', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  // staff see anyone's; an agent sees only their own
  if (!isStaff(sess) && sess.agentId !== req.params.id) {
    console.warn(`[security] agent ${sess.agentId} blocked reading HR record ${req.params.id}`);
    return res.status(403).json({ error: 'Not permitted.' });
  }
  let name = '';
  try {
    const { data } = await supabase.from('agents').select('name').eq('id', req.params.id).maybeSingle();
    name = (data && data.name) || '';
  } catch (e) {}
  const rec = await mergedHR(req.params.id, name);
  res.json({ ok: true, hr: hrPublic(rec), keyConfigured: !!HR_KEY });
});

app.post('/api/agent/:id/hr', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess) && sess.agentId !== req.params.id) {
    return res.status(403).json({ error: 'Not permitted.' });
  }
  const b = req.body || {};
  const existing = (await getSetting('agentHR:' + req.params.id)) || {};
  const clean = v => String(v == null ? '' : v).slice(0, 300).trim();

  const rec = { ...existing };
  HR_FIELDS.forEach(f => { if (f in b) rec[f] = clean(b[f]); });
  rec.w9OnFile = b.w9OnFile === true || b.w9OnFile === 'true' || b.w9OnFile === 'yes';

  // Only the broker touches the taxpayer ID. An admin can keep the rest of the
  // record current without ever being handed someone's SSN.
  if (typeof b.tin === 'string' && b.tin.trim()) {
    if (sess.role !== 'broker') {
      return res.status(403).json({ error: 'Only the broker can enter a taxpayer ID.' });
    }
    const digits = b.tin.replace(/[^0-9]/g, '');
    if (digits.length !== 9) {
      return res.status(400).json({ error: 'A TIN is nine digits — an SSN or an EIN.' });
    }
    if (!HR_KEY) {
      return res.status(503).json({
        error: 'HR_ENCRYPTION_KEY is not set on the server, so a taxpayer ID cannot be stored securely. '
             + 'Everything else on this record saved. Add the key in the hosting environment variables first.',
        code: 'no_encryption_key',
      });
    }
    rec.tinEnc = encryptTin(digits);
    rec.tinLast4 = digits.slice(-4);
    console.log(`[hr] broker set a taxpayer ID for ${req.params.id}`);
  }
  if (b.clearTin === true && sess.role === 'broker') {
    delete rec.tinEnc; delete rec.tinLast4;
    console.log(`[hr] broker cleared the taxpayer ID for ${req.params.id}`);
  }

  rec.updatedAt = new Date().toISOString();
  const ok = await setSetting('agentHR:' + req.params.id, rec);
  if (!ok) return res.status(500).json({ error: 'Could not save.' });
  console.log(`[hr] ${sess.name} updated the record for ${req.params.id}`);
  res.json({ ok: true, hr: hrPublic(rec) });
});

/* ---------- 1099 data ----------
   The only route that decrypts a taxpayer ID, and only for the broker.

   IMPORTANT, and the reason this is called a worksheet: you cannot lawfully
   print your own Copy A of a Form 1099-NEC. The IRS requires the scannable
   red-ink original or electronic filing, and a printed substitute Copy A can
   draw a penalty. Copy B — the agent's copy — may be a substitute if it follows
   IRS Publication 1179. So this produces the recipient copy and the figures for
   filing; the filing itself goes through your accountant or a filing service. */
app.post('/api/tax/1099-data', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role !== 'broker') {
    console.warn(`[security] ${sess.agentId} (${sess.role}) blocked from 1099 data`);
    return res.status(403).json({ error: 'Only the broker can see taxpayer IDs.' });
  }
  const ids = Array.isArray((req.body || {}).agentIds) ? req.body.agentIds.slice(0, 200) : [];
  if (!ids.length) return res.status(400).json({ error: 'No agents given.' });

  // names, so a legal name can fall back to the display name
  const names = {};
  try {
    const { data } = await supabase.from('agents').select('id,name').in('id', ids);
    (data || []).forEach(a => { names[a.id] = a.name || ''; });
  } catch (e) {}

  const out = [];
  for (const id of ids) {
    // reads through to what the agent supplied on My details
    const hr = await mergedHR(id, names[id]);
    const tin = hr.tinEnc ? decryptTin(hr.tinEnc) : null;
    out.push({
      agentId: id,
      legalName: hr.legalName || '',
      entityName: hr.entityName || '',
      address1: hr.address1 || '', address2: hr.address2 || '',
      city: hr.city || '', state: hr.state || '', zip: hr.zip || '',
      tinType: hr.tinType || '',
      tin: tin || '',
      tinFormatted: tin
        ? (hr.tinType === 'EIN' ? tin.slice(0,2) + '-' + tin.slice(2)
                                : tin.slice(0,3) + '-' + tin.slice(3,5) + '-' + tin.slice(5))
        : '',
      w9OnFile: !!hr.w9OnFile, w9Date: hr.w9Date || '',
      missing: [
        hr.legalName ? null : 'legal name',
        hr.address1 ? null : 'address',
        tin ? null : 'taxpayer ID',
        hr.w9OnFile ? null : 'W-9 on file',
      ].filter(Boolean),
    });
  }
  console.log(`[tax] broker generated 1099 data for ${out.length} agent(s)`);
  res.json({
    ok: true, rows: out,
    payer: {
      name: BROKERAGE_LEGAL_ENTITY,
      tradeName: BROKERAGE_NAME,
      phone: BROKERAGE_PHONE,
      ein: process.env.BROKERAGE_EIN || '',
    },
    note: 'Copy A must be filed on the official scannable form or electronically. '
        + 'This worksheet is for the recipient copy and for your accountant.',
  });
});

/* An agent's own 1099 details, for their own recipient copy. Deliberately does
   NOT decrypt the taxpayer ID — they already know their own number, their
   accountant will have it, and sending it back to a browser adds risk for no
   gain. Last four is enough to confirm the right record. */
app.get('/api/tax/my-1099', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;

  /* "View as" changes who the browser is showing, but the session is still the
     broker's — so this used to answer with the broker's own details while the
     figures on screen belonged to the agent being viewed. A 1099 naming the wrong
     recipient is about as bad as this gets, so the agent may be named explicitly,
     and only staff may name anyone but themselves. */
  const asked = String((req.query || {}).agentId || '').trim();
  let who = sess.agentId, whoName = sess.name;
  if (asked && asked !== sess.agentId) {
    if (!isStaff(sess)) {
      console.warn(`[security] ${sess.agentId} tried to read 1099 details for ${asked}`);
      return res.status(403).json({ error: 'Not permitted.' });
    }
    who = asked;
    try {
      const { data } = await supabase.from('agents').select('name').eq('id', who).maybeSingle();
      whoName = (data && data.name) || '';
    } catch (e) { whoName = ''; }
  }

  const hr = await mergedHR(who, whoName);
  res.json({
    ok: true,
    recipient: {
      legalName: hr.legalName || whoName || '',
      entityName: hr.entityName || '',
      address1: hr.address1 || '', address2: hr.address2 || '',
      city: hr.city || '', state: hr.state || '', zip: hr.zip || '',
      tinLast4: hr.tinLast4 || '',
      tinType: hr.tinType || '',
      w9OnFile: !!hr.w9OnFile,
      missing: [
        hr.legalName ? null : 'legal name',
        hr.address1 ? null : 'address',
        hr.tinLast4 ? null : 'taxpayer ID',
        hr.w9OnFile ? null : 'W-9',
      ].filter(Boolean),
    },
    payer: {
      name: BROKERAGE_LEGAL_ENTITY,
      tradeName: BROKERAGE_NAME,
      phone: BROKERAGE_PHONE,
      ein: process.env.BROKERAGE_EIN || '',
    },
  });
});

/* ---------- transaction tracker ----------
   A client-facing timeline the agent drives with one tap per milestone.

   Reached by a signed link rather than a login: someone looking for reassurance
   late at night will not reset a forgotten password, and a tracker nobody opens
   is worth nothing. The token is the only secret, so it is long, it is never
   listed, and the public view returns only what the client should see — no agent
   notes marked private, no internal ids, no other deals.

   Stored as tracker:<agentId>:<id>, with trackerTok:<token> as a pointer so the
   public route can find it without scanning. */
/* Both ends of the same deal. Most of a transaction is shared — contract, earnest
   money, inspection, appraisal, financing, title, closing — so this is the common
   spine rather than two lists stapled together. */
const TRACK_STEPS_BOTH = [
  { k:'accepted',    label:'Under contract',          blurb:'Both sides have signed.' },
  { k:'earnest',     label:'Earnest money in escrow', blurb:'The deposit is held.' },
  { k:'inspection',  label:'Inspection scheduled',    blurb:'An inspector is booked.' },
  { k:'inspected',   label:'Inspection complete',     blurb:'The report is in.' },
  { k:'repairs',     label:'Repairs agreed',          blurb:'Both sides have settled what gets fixed.' },
  { k:'contingency', label:'Inspection period passed',blurb:'That window has closed.' },
  { k:'appraisal',   label:'Appraisal ordered',       blurb:'The lender is checking the value.' },
  { k:'appraised',   label:'Appraisal received',      blurb:'The value came back.' },
  { k:'loan',        label:'Financing approved',      blurb:'The lender has signed off.' },
  { k:'title',       label:'Title work submitted',    blurb:'Ownership records are being checked.' },
  { k:'cleartoclose',label:'Clear to close',          blurb:'Everything is signed off.' },
  { k:'closing',     label:'Closing scheduled',       blurb:'A date and time are set.' },
  { k:'closed',      label:'Closed',                  blurb:'Done.' },
];

/* Things that come up mid-deal and cannot be predicted at the start. The agent
   drops one in where it belongs rather than living with a fixed list. */
const TRACK_EXTRAS = [
  { k:'addendum_sent',   label:'Addendum sent',          blurb:'A change to the contract is with the other side.' },
  { k:'addendum_signed', label:'Addendum signed',        blurb:'That change is agreed by everyone.' },
  { k:'counter',         label:'Counter-offer sent',     blurb:'We have countered.' },
  { k:'survey',          label:'Survey ordered',         blurb:'A surveyor is checking the boundaries.' },
  { k:'hoa',             label:'HOA documents received', blurb:'The association paperwork has come through.' },
  { k:'insurance',       label:'Insurance bound',        blurb:'Cover is in place for closing.' },
  { k:'wind',            label:'Wind mitigation done',   blurb:'The inspection that affects your premium is complete.' },
  { k:'flood',           label:'Flood determination',    blurb:'The flood zone has been confirmed.' },
  { k:'repair_request',  label:'Repair request sent',    blurb:'We have asked for repairs in writing.' },
  { k:'repair_done',     label:'Repairs completed',      blurb:'The work is finished.' },
  { k:'utilities',       label:'Utilities transferred',  blurb:'Services are being switched over.' },
  { k:'funds',           label:'Closing funds sent',     blurb:'The money is on its way to the closing table.' },
];

const TRACK_STEPS = {
  buy: [
    { k:'offer',       label:'Offer submitted',            blurb:'Your offer is with the seller.' },
    { k:'accepted',    label:'Offer accepted',             blurb:'They said yes. The clock starts here.' },
    { k:'earnest',     label:'Earnest money delivered',    blurb:'Your deposit is held in escrow.' },
    { k:'inspection',  label:'Inspection scheduled',       blurb:'An inspector is booked to look the house over.' },
    { k:'inspected',   label:'Inspection complete',        blurb:'The report is in.' },
    { k:'contingency', label:'Inspection period passed',   blurb:'Anything to be fixed has been agreed.' },
    { k:'appraisal',   label:'Appraisal ordered',          blurb:'The lender is checking the value.' },
    { k:'appraised',   label:'Appraisal received',         blurb:'The value came back.' },
    { k:'loan',        label:'Loan approved',              blurb:'The lender has approved your financing.' },
    { k:'title',       label:'Title work submitted',       blurb:'The title company is checking ownership records.' },
    { k:'cleartoclose',label:'Clear to close',             blurb:'Everything is signed off. Closing can be scheduled.' },
    { k:'walkthrough', label:'Final walkthrough',          blurb:'One last look before it is yours.' },
    { k:'keys',        label:'Keys',                       blurb:'It is yours.' },
  ],
  sell: [
    { k:'listed',      label:'Listed',                     blurb:'Your home is on the market.' },
    { k:'showings',    label:'Showings underway',          blurb:'Buyers are coming through.' },
    { k:'offer',       label:'Offer received',             blurb:'An offer has come in.' },
    { k:'accepted',    label:'Offer accepted',             blurb:'Under contract.' },
    { k:'earnest',     label:'Buyer\u2019s deposit received',  blurb:'Their earnest money is in escrow.' },
    { k:'inspection',  label:'Inspection period',          blurb:'The buyer is having the home inspected.' },
    { k:'repairs',     label:'Repairs agreed',             blurb:'Any repairs have been settled.' },
    { k:'appraised',   label:'Appraisal complete',         blurb:'The lender\u2019s valuation is done.' },
    { k:'loan',        label:'Buyer financing cleared',    blurb:'Their loan is approved.' },
    { k:'title',       label:'Title work submitted',       blurb:'The title company is checking ownership records.' },
    { k:'cleartoclose',label:'Clear to close',             blurb:'Everything is signed off.' },
    { k:'closed',      label:'Closed',                     blurb:'Sold. Congratulations.' },
  ],
  both: TRACK_STEPS_BOTH,
};

/* The step list lives on the tracker itself rather than in this file, so it can be
   edited per deal. Older trackers were stored as a milestones map against the
   template; this brings them forward without anyone having to do anything. */
function trackerSteps(t){
  if (Array.isArray(t.steps) && t.steps.length) return t.steps;
  const defs = TRACK_STEPS[t.side] || TRACK_STEPS.buy;
  return defs.map(d => {
    const m = (t.milestones || {})[d.k] || {};
    return { k:d.k, label:d.label, blurb:d.blurb,
             done:!!m.done, date:m.date||'', note:m.note||'',
             private:!!m.private, at:m.at||'' };
  });
}

function trackerPublic(t){
  const steps = trackerSteps(t);
  return {
    id: t.id,
    side: t.side,
    address: t.address || '',
    clientName: t.clientName || '',
    agentName: t.agentName || '',
    agentPhone: t.agentPhone || BROKERAGE_PHONE,
    agentEmail: t.agentEmail || '',
    agentSlug: t.agentSlug || '',
    expectedClose: t.expectedClose || '',
    brokerage: BROKERAGE_NAME,
    updatedAt: t.updatedAt || '',
    steps: steps.map(sd => ({
      k: sd.k, label: sd.label, blurb: sd.blurb || '',
      done: !!sd.done,
      date: sd.date || '',
      // notes marked private stay in the CRM
      note: (sd.note && !sd.private) ? sd.note : '',
      at: sd.at || '',
    })),
  };
}

/* Every address on the deal, both sides, de-duplicated. */
function trackerRecipients(t){
  const out = [];
  [t.clientEmail, t.clientEmail2].forEach(field => {
    String(field || '').split(/[,;]/).forEach(e => {
      const v = e.trim();
      if (v && v.includes('@') && !out.includes(v)) out.push(v);
    });
  });
  return out.slice(0, 8);
}

function newTrackerToken(){
  return crypto.randomBytes(18).toString('hex');
}

/* Agent creates a tracker. */
app.post('/api/tracker', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const side = ['sell','both'].includes(b.side) ? b.side : 'buy';
  const clean = v => String(v == null ? '' : v).slice(0, 200).trim();

  const id = 'tr_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
  const token = newTrackerToken();
  const rec = {
    id, token, side,
    agentId: sess.agentId,
    agentName: sess.name || '',
    agentEmail: sess.email || '',
    address: clean(b.address),
    clientName: clean(b.clientName),
    clientEmail: clean(b.clientEmail),
    /* A side of a transaction is rarely one person \u2014 spouses, partners, a parent
       helping with the purchase. Emails are comma-separated, and a both-sides deal
       carries a second party as well. */
    clientName2: clean(b.clientName2),
    clientEmail2: clean(b.clientEmail2),
    expectedClose: clean(b.expectedClose),
    steps: (TRACK_STEPS[side] || TRACK_STEPS.buy).map(d => ({
      k:d.k, label:d.label, blurb:d.blurb,
      done:false, date:'', note:'', private:false, at:'',
    })),
    pending: [],          // marked done but not yet sent to the client
    milestones: {},       // kept for anything written before steps existed
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await setSetting('tracker:' + sess.agentId + ':' + id, rec);
  await setSetting('trackerTok:' + token, { key: 'tracker:' + sess.agentId + ':' + id });
  console.log(`[tracker] ${sess.name} started a ${side} tracker for ${rec.clientName || 'a client'}`);
  res.json({ ok: true, tracker: rec });
});

/* Agent marks a step.

   This deliberately does NOT email. Marking three things in a row used to fire
   three emails back to back, which is exactly the sort of thing that makes a
   client mute you. Completed steps queue up in `pending` and go out as one
   message when the agent presses send. */
app.post('/api/tracker/:id/step', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'tracker:' + sess.agentId + ':' + String(req.params.id || '');
  const t = await getSetting(key);
  if (!t) return res.status(404).json({ error: 'Tracker not found.' });

  const b = req.body || {};
  const stepKey = String(b.step || '');
  t.steps = trackerSteps(t);
  const step = t.steps.find(x => x.k === stepKey);
  if (!step) return res.status(400).json({ error: 'Unknown step.' });

  const was = !!step.done;
  const done = b.done !== false;

  step.done = done;
  if (b.date !== undefined) step.date = String(b.date || '').slice(0, 20);
  if (b.note !== undefined) step.note = String(b.note || '').slice(0, 600);
  if (b.private !== undefined) step.private = !!b.private;
  step.at = new Date().toISOString();

  t.pending = Array.isArray(t.pending) ? t.pending : [];
  if (done && !was && !t.pending.includes(stepKey)) t.pending.push(stepKey);
  if (!done) t.pending = t.pending.filter(k => k !== stepKey);

  t.updatedAt = new Date().toISOString();
  await setSetting(key, t);
  res.json({ ok: true, tracker: t, pending: t.pending.length });
});

/* One email covering everything marked since the last one. */
app.post('/api/tracker/:id/notify', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'tracker:' + sess.agentId + ':' + String(req.params.id || '');
  const t = await getSetting(key);
  if (!t) return res.status(404).json({ error: 'Tracker not found.' });
  const recipients = trackerRecipients(t);
  if (!recipients.length) return res.status(400).json({ error: 'No client email on this one.' });
  if (!mailer) return res.status(503).json({ error: 'Email is not set up.' });

  const steps = trackerSteps(t);
  const pending = (Array.isArray(t.pending) ? t.pending : [])
    .map(k => steps.find(s => s.k === k)).filter(Boolean);
  if (!pending.length) return res.status(400).json({ error: 'Nothing new to tell them.' });

  const origin = `${req.protocol}://${req.get('host')}`;
  const link = `${origin}/?track=${t.token}`;
  // "Hi Dawn and Marcus" when both sides are on the same deal
  const names = [t.clientName, t.clientName2].map(x => String(x||'').trim().split(/\s+/)[0])
                  .filter(Boolean);
  const first = names.length > 1 ? names.slice(0,-1).join(', ') + ' and ' + names.slice(-1)
              : (names[0] || 'there');
  const done = steps.filter(s => s.done).length;

  const lines = pending.map(s => {
    const note = (s.note && !s.private) ? `\n    ${s.note}` : '';
    return `  \u2713 ${s.label}\n    ${s.blurb || ''}${note}`;
  }).join('\n\n');

  const headline = pending.length === 1
    ? pending[0].label
    : `${pending.length} updates on ${t.address || 'your move'}`;

  try {
    await mailer.sendMail({
      to: recipients,
      subject: `${headline}${pending.length === 1 && t.address ? ' \u2014 ' + t.address : ''}`,
      text: `Hi ${first},\n\n`
          + (pending.length === 1 ? `Progress:\n\n` : `A few things have moved:\n\n`)
          + lines
          + `\n\nThat puts you ${done} of ${steps.length} steps through.\n\n`
          + `You can see the whole picture any time:\n${link}\n\n`
          + `Any questions, just reply or call.\n\n`
          + `${t.agentName || sess.name || ''}\n${BROKERAGE_NAME}\n${t.agentPhone || BROKERAGE_PHONE}`,
    });
  } catch (e) {
    console.error('[tracker] notify failed:', e.message);
    return res.status(500).json({ error: 'Could not send that.' });
  }

  t.pending = [];
  t.lastNotified = new Date().toISOString();
  await setSetting(key, t);
  console.log(`[tracker] ${sess.name} sent ${pending.length} update(s) to ${recipients.length} recipient(s)`);
  res.json({ ok: true, sent: pending.length });
});

/* Add, rename, reorder or remove steps. A deal throws up things no template
   predicts \u2014 addendums going back and forth, a survey, an HOA packet. */
app.post('/api/tracker/:id/steps', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'tracker:' + sess.agentId + ':' + String(req.params.id || '');
  const t = await getSetting(key);
  if (!t) return res.status(404).json({ error: 'Tracker not found.' });

  const incoming = Array.isArray((req.body || {}).steps) ? req.body.steps : null;
  if (!incoming) return res.status(400).json({ error: 'No steps given.' });
  if (incoming.length > 40) return res.status(400).json({ error: 'Forty steps is plenty.' });

  const existing = trackerSteps(t);
  const seen = new Set();
  t.steps = incoming.map(s => {
    let k = String(s.k || '').replace(/[^a-z0-9_]/gi, '').slice(0, 40)
            || 'step_' + Math.random().toString(36).slice(2, 8);
    while (seen.has(k)) k += '_2';
    seen.add(k);
    const was = existing.find(x => x.k === k) || {};
    return {
      k,
      label: String(s.label || was.label || 'Step').slice(0, 90),
      blurb: String(s.blurb !== undefined ? s.blurb : (was.blurb || '')).slice(0, 200),
      done: was.done || false,
      date: was.date || '', note: was.note || '',
      private: !!was.private, at: was.at || '',
      custom: !!s.custom || !!was.custom,
    };
  });
  // a step that has gone should not still be queued
  t.pending = (Array.isArray(t.pending) ? t.pending : []).filter(k => seen.has(k));
  t.updatedAt = new Date().toISOString();
  await setSetting(key, t);
  res.json({ ok: true, tracker: t });
});

app.get('/api/tracker/extras', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  res.json({ ok: true, extras: TRACK_EXTRAS });
});

app.get('/api/tracker/mine', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const out = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value')
      .ilike('key', 'tracker:' + sess.agentId + ':%');
    (data || []).forEach(r => { if (r.value) out.push(r.value); });
  } catch (e) { console.error('[tracker] list failed:', e.message); }
  out.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
  res.json({ ok: true, trackers: out });
});

app.delete('/api/tracker/:id', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'tracker:' + sess.agentId + ':' + String(req.params.id || '');
  const t = await getSetting(key);
  if (t && t.token) {
    try { await supabase.from(KV_TABLE).delete().eq('key', 'trackerTok:' + t.token); } catch (e) {}
  }
  try { await supabase.from(KV_TABLE).delete().eq('key', key); } catch (e) {}
  res.json({ ok: true });
});

/* The client's view. No session \u2014 the token is the key. */
app.get('/api/track/:token', async (req, res) => {
  const token = String(req.params.token || '').replace(/[^a-f0-9]/gi, '');
  if (token.length < 20) return res.status(404).json({ error: 'Not found.' });
  const ptr = await getSetting('trackerTok:' + token);
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const t = await getSetting(ptr.key);
  if (!t) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true, tracker: trackerPublic(t) });
});

/* ---------- playbooks ----------
   Separate sequences per situation rather than one buyer drip and one seller
   drip. A person who has looked at seventeen houses should not get the same
   first message as somebody who filled in a form and left.

   Stored at settings:playbooks so a broker edits wording, timing and questions
   without anybody touching this file. These are the defaults it starts from.

   \u26a0 Every question is one a person can answer in four words. That is the whole
   trick: "Local or relocating?" gets a reply; "Would you like to schedule a
   buyer consultation?" does not. */
const PLAYBOOK_DEFAULTS = [
  { id:'pb_prop', name:'Asked about one property', match:{ source:'listing' }, steps:[
    { d:0,  ch:'sms',   t:"Hey {first}, it's {agent}. Saw you were looking at {address}. Quick one \u2014 is it that one specifically, or are you looking at a few?" },
    { d:1,  ch:'email', s:'{address}', t:"Hi {first},\n\nA few things about {address} that aren't in the listing \u2014 what the building's actually like, what the fees cover, and what's sold near it lately.\n\nWant me to send those over? And is it that one you're set on, or are you still comparing?" },
    { d:3,  ch:'sms',   t:"{first} \u2014 one thing so I don't send you a load of stuff you don't want. Staying around {city}, or open to nearby?" },
    { d:6,  ch:'task',  t:'Call them. Six days, no reply \u2014 a call gets through where texts do not.' },
    { d:10, ch:'sms',   t:"Random one: what's the ONE thing a place has to have for you?" },
    { d:18, ch:'email', s:'A few that are not just what came up first', t:"Hi {first},\n\nI've pulled a handful that don't just happen to be top of the search results. Want them?" },
    { d:30, ch:'sms',   t:"{first}, I don't want to be the agent blowing up your phone. Want me to keep an eye out for you, or should I leave you alone for now?" },
  ]},
  { id:'pb_buyer', name:'New buyer, no property named', match:{ source:'new' }, steps:[
    { d:0,  ch:'sms',   t:"Hey {first}, it's {agent} at {brokerage}. Are you already local, or would this be a move down here?" },
    { d:1,  ch:'sms',   t:"Also \u2014 rough idea on budget? Under $400k, $400\u2013500k, $500k+, or still working that out?" },
    { d:4,  ch:'email', s:'Where to actually look', t:"Hi {first},\n\nThe stretch from Fort Morgan to Perdido Key is really five or six different markets, and the difference matters more than people expect.\n\nTell me roughly what you're after and I'll tell you which bit fits." },
    { d:8,  ch:'task',  t:'Call them.' },
    { d:15, ch:'sms',   t:"{first} \u2014 this year, or more of a someday thing? Either is fine, it just changes what I send." },
    { d:30, ch:'sms',   t:"Want me to keep looking for you, or should I leave you alone for now?" },
  ]},
  { id:'pb_seller', name:'Asked what their home is worth', match:{ source:'value' }, steps:[
    { d:0,  ch:'sms',   t:"Hey {first}, it's {agent}. Got your request about {address}. Before I send you automated numbers that may or may not be right \u2014 are you actually thinking of selling, or mostly curious what it'd fetch?" },
    { d:1,  ch:'email', s:'About {address}', t:"Hi {first},\n\nI can give you a proper number, but an accurate one needs two things a computer doesn't know: what you've done to it, and when you'd want to move.\n\nTell me those and I'll do it properly rather than guessing." },
    { d:4,  ch:'sms',   t:"{first} \u2014 would knowing what you'd actually WALK AWAY WITH after everything be more use than a sale price?" },
    { d:9,  ch:'task',  t:'Call them. Sellers convert on the phone far more than by email.' },
    { d:16, ch:'sms',   t:"If the number made sense, would you actually move? Or is it more of a maybe-someday?" },
    { d:30, ch:'email', s:'What has sold near you', t:"Hi {first},\n\nHere's what's actually sold near {address} recently \u2014 useful whether you sell this year or in five.\n\nAnything changed on your end?" },
  ]},
  { id:'pb_oh', name:'Signed in at an open house', match:{ source:'open-house' }, steps:[
    { d:0,  ch:'sms',   t:"Hey {first}, {agent} here \u2014 thanks for coming by {address} today. Was it close to what you're after, or not quite?" },
    { d:2,  ch:'email', s:'After {address}', t:"Hi {first},\n\nThanks again for coming through. Two questions and I'll get out of your way:\n\nWas it close? And is there something you've seen elsewhere it should be measured against?" },
    { d:7,  ch:'sms',   t:"{first} \u2014 a couple more have come up in that range. Want me to send them?" },
    { d:14, ch:'task',  t:'Call them.' },
    { d:30, ch:'sms',   t:"Want me to keep an eye out, or leave you to it?" },
  ]},
  { id:'pb_quiet', name:'Registered, then nothing', match:{ source:'exit-intent' }, steps:[
    { d:0,  ch:'email', s:'Nothing to sign up for', t:"Hi {first},\n\nYou asked to hear about new listings, so that's what I'll send \u2014 nothing else, and you can stop them any time.\n\nOne question so they're useful: buying, selling, or just watching?" },
    { d:5,  ch:'sms',   t:"{first} \u2014 house or condo? Helps me send the right things." },
    { d:12, ch:'sms',   t:"This year, or just researching for now?" },
    { d:28, ch:'sms',   t:"Want me to keep these coming, or stop them? Either's fine." },
  ]},
  { id:'pb_back', name:'Went quiet, then came back', match:{ source:'reactivated' }, steps:[
    { d:0,  ch:'sms',   t:"Hey {first} \u2014 saw you were back on the site. Anything changed on your end, or still having a look?" },
    { d:2,  ch:'task',  t:'Call them. Somebody who comes back after months is worth a call the same week.' },
  ]},
  /* ---------- past day 30 ----------
     Everything above stops at day 30, which left the long-term nurture lane with
     nothing to send but conversation starters on repeat. These are the other job:
     a reason to be in the inbox when somebody is not transacting yet.

     Syndicated newsletters lose here. Big Macs and bathroom plants could come
     from any agent in the country. Insurance costs, what a specific building's
     fees actually cover, and what sold in it last month could only come from
     someone who works this coast \u2014 which is the whole point. */
  { id:'pb_nurture', name:'Long-term nurture \u2014 monthly, local', match:{ lane:'slow' }, steps:[
    { d:30,  ch:'email', s:'What insurance actually costs down here',
      t:"Hi {first},\n\nThe thing that catches most people out on this coast is not the price of the house, it is the insurance on it. Wind, flood and hail are usually three separate conversations, and the difference between a house a mile inland and one on the beach can be thousands a year.\n\nIf you want, tell me a street or a building and I will tell you roughly what people are paying there now.\n\n{agent}" },
    { d:60,  ch:'email', s:'What actually sold near you last month',
      t:"Hi {first},\n\nNot a market report with charts \u2014 just what actually changed hands around {city} recently and what it went for.\n\nAsking prices tell you what sellers hope for. Sold prices tell you what the market agreed to. Want me to send the sold list for a particular street or building?\n\n{agent}" },
    { d:90,  ch:'email', s:'Condo fees: what you are really buying',
      t:"Hi {first},\n\nTwo buildings on the same stretch of beach can have fees hundreds apart, and the higher one is sometimes the better deal \u2014 it depends entirely on what the fee covers and what the reserves look like.\n\nI keep notes on the buildings around here: what is included, what has gone up lately, and which ones have assessments coming.\n\nAny building you want the honest version on?\n\n{agent}" },
    { d:120, ch:'email', s:'Before hurricane season',
      t:"Hi {first},\n\nA short and genuinely useful one. Whether you own here or are still looking, these are the things worth sorting before the season: check your wind mitigation certificate is current, photograph the property inside and out, and know your deductible \u2014 hurricane deductibles are usually a percentage, not a flat number, and people are surprised by that at the worst moment.\n\nHappy to look yours over.\n\n{agent}" },
    { d:150, ch:'task', t:'Six months. Call them \u2014 not to sell, just to ask how the search is going.' },
    { d:180, ch:'email', s:'Fort Morgan, Gulf Shores or Perdido Key?',
      t:"Hi {first},\n\nPeople treat this as one beach. It is really five or six markets, and the difference matters more than most people expect \u2014 rental rules, traffic in season, how much house you get, how quiet it is in February.\n\nIf you tell me how you would actually use the place, I will tell you which stretch fits and which to skip.\n\n{agent}" },
    { d:240, ch:'email', s:'What rentals actually bring in',
      t:"Hi {first},\n\nIf a rental is any part of the plan, the numbers people quote are usually gross and the ones that matter are net \u2014 after management, fees, insurance, and the weeks you want it yourself.\n\nI can put real numbers on a specific building rather than the brochure version. Want me to?\n\n{agent}" },
    { d:300, ch:'task', t:'Ten months. Worth a call to find out whether anything has changed.' },
    { d:365, ch:'email', s:'A year on \u2014 still worth keeping an eye out?',
      t:"Hi {first},\n\nIt has been about a year. I am still happy to keep watching for you, but I would rather ask than keep sending.\n\nStill worth it, or should I leave you be for a while?\n\n{agent}" },
  ]},

  { id:'pb_seller_slow', name:'Seller who is not ready yet', match:{ type:'seller' }, steps:[
    { d:30, ch:'email', s:'No rush \u2014 but here is what your street is doing',
      t:"Hi {first},\n\nNo pitch. You asked what the place was worth, and things have moved since.\n\nHere is what has sold near you and how long each took. If you are still a year out, that is fine \u2014 this is just so the number in your head stays roughly right.\n\n{agent}" },
    { d:90, ch:'email', s:'The three things that move the number most',
      t:"Hi {first},\n\nWhen you do sell, most of the difference comes down to three things: how it photographs, what the first week of pricing looks like, and whether the obvious objection is dealt with before anyone raises it.\n\nNone of that costs much if it is done early. Happy to walk through yours whenever.\n\n{agent}" },
    { d:180, ch:'task', t:'Six months since the valuation. Call and ask how the plan is looking.' },
    { d:270, ch:'email', s:'Still thinking about it?',
      t:"Hi {first},\n\nJust checking whether selling is still on the cards. If the timing has moved, tell me roughly when and I will stop guessing.\n\n{agent}" },
  ]},

  { id:'pb_snowbird', name:'Snowbird \u2014 back in season', match:{ tag:'snowbird' }, steps:[
    { d:30,  ch:'email', s:'Quiet season is the good season to buy',
      t:"Hi {first},\n\nCounterintuitive one: the stretch between November and February is usually when the better deals happen here. Less competition, sellers who have sat through a season, and you get to see the place when it is quiet rather than when it is at its best.\n\nWorth a look while you are down?\n\n{agent}" },
    { d:120, ch:'task', t:'Season is coming. Call before they book the trip, not after.' },
    { d:150, ch:'email', s:'Want me to line a few up for when you are down?',
      t:"Hi {first},\n\nIf you are heading down this season, tell me the dates and roughly what you want to see and I will have a handful lined up rather than you spending the first two days working out where to look.\n\n{agent}" },
  ]},

  { id:'pb_sphere', name:'Past client \u2014 stay in touch', match:{ type:'client' }, steps:[
    { d:90,  ch:'task', t:'Three months in. Call \u2014 ask about the house, not about referrals.' },
    { d:180, ch:'email', s:'How is the place treating you?',
      t:"Hi {first},\n\nNo agenda. Just wondering how the place is treating you and whether anything needs sorting.\n\nIf you ever need a name for anything \u2014 roofer, insurance, someone to look at the deck \u2014 I keep a list of people I would actually use myself.\n\n{agent}" },
    { d:365, ch:'email', s:'A year in {city}',
      t:"Hi {first},\n\nA year since you closed. Values around you have moved, so here is where things stand if you are curious \u2014 no pitch attached.\n\n{agent}" },
  ]},
];

/* ---------- lead scoring ----------
   A number between 0 and 100 built from things the lead actually did, not a
   prediction. Every point is traceable to an event, which is why the agent alert
   can say WHY somebody went hot rather than just that they did.

   \u26a0 The score never sends anything on its own. It sorts the list and it decides
   when to fetch a human. Automation starts conversations; agents have them. */
const SCORE_EVENTS = {
  sms_reply:        { pts: 15, why: 'replied to a text' },
  email_reply:      { pts: 15, why: 'replied to an email' },
  showing_request:  { pts: 30, why: 'asked to see a property' },
  agent_call_req:   { pts: 30, why: 'asked to speak to someone' },
  seller_definite:  { pts: 25, why: 'has definite plans to sell' },
  timeline_90:      { pts: 20, why: 'moving within 90 days' },
  financing:        { pts: 15, why: 'mentioned financing or pre-approval' },
  article_click:    { pts:  6, why: 'read something we sent' },
  favorited:        { pts:  8, why: 'saved a property' },
  visits_multi:     { pts:  8, why: 'been back to the site several times' },
  repeat_view:      { pts:  5, why: 'looked at the same property again' },
  email_open:       { pts:  2, why: 'opened an email' },
  form_again:       { pts: 10, why: 'filled in another form' },
};

const SCORE_BANDS = [
  { at: 80, key: 'priority', label: 'Needs you now' },
  { at: 60, key: 'hot',      label: 'Hot' },
  { at: 40, key: 'warm',     label: 'Warm' },
  { at: 20, key: 'engaged',  label: 'Engaged' },
  { at:  0, key: 'nurture',  label: 'Nurture' },
];

function scoreBand(n){
  return SCORE_BANDS.find(b => n >= b.at) || SCORE_BANDS[SCORE_BANDS.length - 1];
}

/* Quiet for a long time should cost something, or every old lead eventually
   looks hot. Decays after three weeks of nothing, floored so it never inverts. */
function scoreDecay(lastActivity){
  if (!lastActivity) return 0;
  const days = Math.floor((Date.now() - new Date(lastActivity).getTime()) / 86400000);
  if (days < 21) return 0;
  return Math.min(30, Math.floor((days - 21) / 7) * 5);
}

function leadScore(lead){
  const events = Array.isArray(lead.events) ? lead.events : [];
  const raw = events.reduce((a, e) => a + ((SCORE_EVENTS[e.k] || {}).pts || 0), 0);
  const n = Math.max(0, Math.min(100, raw - scoreDecay(lead.lastActivity)));
  return { score: n, band: scoreBand(n) };
}

/* The sentence the agent actually reads. Built from the highest-value events, so
   it says what changed rather than that something did. */
function scoreWhy(lead, limit){
  const events = (Array.isArray(lead.events) ? lead.events : [])
    .slice().reverse()
    .filter((e, i, a) => a.findIndex(x => x.k === e.k) === i)
    .sort((a, b) => ((SCORE_EVENTS[b.k]||{}).pts||0) - ((SCORE_EVENTS[a.k]||{}).pts||0))
    .slice(0, limit || 3);
  return events.map(e => (SCORE_EVENTS[e.k] || {}).why).filter(Boolean);
}

app.get('/api/playbooks', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const saved = await getSetting('settings:playbooks');
  res.json({ ok: true, playbooks: Array.isArray(saved) && saved.length ? saved : PLAYBOOK_DEFAULTS,
             usingDefaults: !(Array.isArray(saved) && saved.length) });
});

app.post('/api/playbooks', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Only the broker can change these.' });
  const list = Array.isArray((req.body || {}).playbooks) ? req.body.playbooks : null;
  if (!list) return res.status(400).json({ error: 'Nothing given.' });
  await setSetting('settings:playbooks', list.slice(0, 40));
  console.log(`[playbooks] ${sess.name} saved ${list.length}`);
  res.json({ ok: true });
});

app.post('/api/lead/:id/event', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'lead:' + String(req.params.id || '');
  const lead = await getSetting(key);
  if (!lead) return res.status(404).json({ error: 'Lead not found.' });
  if (!isStaff(sess) && lead.assignedAgentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not permitted.' });
  }
  const k = String((req.body || {}).event || '');
  if (!SCORE_EVENTS[k]) return res.status(400).json({ error: 'Unknown event.' });

  lead.events = Array.isArray(lead.events) ? lead.events : [];
  lead.events.push({ k, at: new Date().toISOString(), note: String((req.body||{}).note || '').slice(0,200) });
  lead.lastActivity = new Date().toISOString();

  /* A reply means a person is talking. This used to set drip.stopped and end the
     sequence for good, which quietly dropped leads out of the system — against
     the rule that nothing ever stops unless an agent or the client says so.
     It now moves them to the 'conversation' lane: no canned email while the
     agent is mid-conversation, but listing alerts keep running and the lead is
     still on a plan the moment the agent hands them back. */
  if (k === 'sms_reply' || k === 'email_reply' || k === 'showing_request' || k === 'agent_call_req') {
    lead.humanTakeover = new Date().toISOString();
  }

  const { score, band } = leadScore(lead);
  lead.score = score; lead.band = band.key;
  try { laneApply(lead, Date.now()); } catch (e) { console.error('[lane]', e.message); }
  await setSetting(key, lead);
  res.json({ ok: true, score, band, why: scoreWhy(lead) });
});

/* ---------- saved searches ----------
   An agent sets up what a lead is looking for once. New listings that match are
   emailed at whatever pace the lead wants. The lead can change that pace or stop
   entirely from a link in every message, without anybody's help.

   Runs off the same tick as the follow-up sequences — no scheduler on this host. */
function searchFilter(c){
  const parts = [ACTIVE_ONLY];
  const esc = v => String(v).replace(/'/g, "''");
  // several towns reads as "any of these", not "all of these"
  if (Array.isArray(c.cities) && c.cities.length) {
    parts.push('(' + c.cities.map(t => `contains(City,'${esc(t)}')`).join(' or ') + ')');
  } else if (c.city) {
    parts.push(`contains(City,'${esc(c.city)}')`);
  }
  if (c.minPrice) parts.push(`ListPrice ge ${Number(c.minPrice)}`);
  if (c.maxPrice) parts.push(`ListPrice le ${Number(c.maxPrice)}`);
  if (c.beds)     parts.push(`BedroomsTotal ge ${Number(c.beds)}`);
  if (c.baths)    parts.push(`BathroomsTotalInteger ge ${Number(c.baths)}`);
  if (c.type)     parts.push(`PropertyType eq '${esc(c.type)}'`);
  if (c.waterfront) parts.push('WaterfrontYN eq true');
  /* ⚠ Everything below was collected by the form and then ignored here, so the
     alert a client received was looser than the one the agent set up. */
  if (c.pool)     parts.push('PoolPrivateYN eq true');
  if (c.view)     parts.push('ViewYN eq true');
  if (c.newConstruction) parts.push('NewConstructionYN eq true');
  if (c.noHoa)    parts.push('AssociationYN eq false');
  if (c.garage)   parts.push(`GarageSpaces ge ${Number(c.garage)}`);
  if (c.stories)  parts.push(`StoriesTotal ge ${Number(c.stories)}`);
  if (c.acres)    parts.push(`LotSizeAcres ge ${Number(c.acres)}`);
  if (c.sqft)     parts.push(`LivingArea ge ${Number(c.sqft)}`);
  if (c.maxSqft)  parts.push(`LivingArea le ${Number(c.maxSqft)}`);
  if (c.yearBuilt) parts.push(`YearBuilt ge ${Number(c.yearBuilt)}`);
  if (c.maxHoa)   parts.push(`AssociationFee le ${Number(c.maxHoa)}`);
  if (c.since)    parts.push(`OnMarketDate gt ${c.since}`);
  return parts.join(' and ');
}

function searchLabel(c){
  const bits = [];
  if (Array.isArray(c.cities) && c.cities.length) bits.push(c.cities.join(' or '));
  else if (c.city) bits.push(c.city);
  if (c.beds) bits.push(c.beds + '+ bed');
  if (c.baths) bits.push(c.baths + '+ bath');
  if (c.minPrice || c.maxPrice) {
    const f = n => '$' + Number(n).toLocaleString();
    bits.push(c.minPrice && c.maxPrice ? f(c.minPrice) + '\u2013' + f(c.maxPrice)
      : c.maxPrice ? 'under ' + f(c.maxPrice) : 'over ' + f(c.minPrice));
  }
  if (c.waterfront) bits.push('waterfront');
  if (c.pool) bits.push('pool');
  if (c.view) bits.push('a view');
  if (c.newConstruction) bits.push('new build');
  if (c.noHoa) bits.push('no HOA');
  if (c.sqft) bits.push(c.sqft.toLocaleString() + '+ sq ft');
  if (c.acres) bits.push(c.acres + '+ acres');
  if (c.type) bits.push(c.type);
  return bits.join(' \u00b7 ') || 'anything new';
}

async function searchRun(criteria, sinceISO){
  const token = process.env.BRIDGE_SERVER_TOKEN, dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) return [];
  const c = Object.assign({}, criteria, { since: sinceISO });
  const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
    + `?access_token=${encodeURIComponent(token)}`
    + `&$filter=${encodeURIComponent(searchFilter(c))}`
    + `&$orderby=OnMarketDate desc&$top=12`;
  try {
    const r = await fetch(url);
    if (!r.ok) { console.error('[search] MLS returned', r.status); return []; }
    const j = await r.json();
    return j.value || [];
  } catch (e) { console.error('[search] failed:', e.message); return []; }
}

function searchToken(id){
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('search:' + id).digest('hex').slice(0, 24);
}

app.post('/api/search', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const clean = v => String(v == null ? '' : v).slice(0, 90).trim();
  const num = v => { const n = Number(v); return isFinite(n) && n > 0 ? Math.round(n) : ''; };
  const id = 'ss_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  /* ⚠ This used to keep seven fields and silently drop everything else. The form
     collects pool, garage, stories, acres, sq ft, year built, HOA and the rest,
     posts them correctly, and they were thrown away here — so an alert set up for
     a pool home under $650k sent the client anything under $650k. Every field the
     form can collect is persisted now, and searchFilter() honors all of them. */
  const criteria = {
    city: clean(b.city), type: clean(b.type),
    minPrice: num(b.minPrice), maxPrice: num(b.maxPrice),
    beds: num(b.beds), baths: num(b.baths),
    waterfront: !!b.waterfront, pool: !!b.pool,
    view: !!b.view, newConstruction: !!b.newConstruction, noHoa: !!b.noHoa,
    garage: num(b.garage), stories: num(b.stories),
    acres: num(b.acres), sqft: num(b.sqft), maxSqft: num(b.maxSqft),
    yearBuilt: num(b.yearBuilt), maxHoa: num(b.maxHoa),
  };
  // multi-town: the form lets them add as many as they like
  if (Array.isArray(b.cities) && b.cities.length) {
    criteria.cities = b.cities.map(clean).filter(Boolean).slice(0, 12);
    if (!criteria.city) criteria.city = criteria.cities[0];
  }
  const rec = {
    id, agentId: sess.agentId, agentName: sess.name || '', agentEmail: sess.email || '',
    leadId: clean(b.leadId), name: clean(b.name), email: clean(b.email),
    pace: ['instant','daily','weekly','paused'].includes(b.pace) ? b.pace : 'daily',
    criteria,
    lastSent: new Date().toISOString(),
    sentKeys: [],
    createdAt: new Date().toISOString(),
  };
  if (!rec.email) return res.status(400).json({ error: 'An email address, at least.' });
  await setSetting('savedSearch:' + sess.agentId + ':' + id, rec);
  await setSetting('ssTok:' + searchToken(id), { key: 'savedSearch:' + sess.agentId + ':' + id });
  console.log(`[search] ${sess.name} set up "${searchLabel(rec.criteria)}" for ${rec.name || rec.email}`);
  res.json({ ok: true, search: rec });
});

app.get('/api/search/mine', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const out = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value')
      .ilike('key', 'savedSearch:' + sess.agentId + ':%');
    (data || []).forEach(r => { if (r.value) out.push(Object.assign({ label: searchLabel(r.value.criteria || {}) }, r.value)); });
  } catch (e) {}
  res.json({ ok: true, searches: out });
});

app.delete('/api/search/:id', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'savedSearch:' + sess.agentId + ':' + String(req.params.id || '');
  const rec = await getSetting(key);
  if (rec) {
    try { await supabase.from(KV_TABLE).delete().eq('key', 'ssTok:' + searchToken(rec.id)); } catch (e) {}
    try { await supabase.from(KV_TABLE).delete().eq('key', key); } catch (e) {}
  }
  res.json({ ok: true });
});

/* A preview so the agent sees what the lead will get before anything is sent. */
app.post('/api/search/preview', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const since = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const rows = await searchRun({
    city: b.city, type: b.type, minPrice: b.minPrice, maxPrice: b.maxPrice,
    beds: b.beds, baths: b.baths, waterfront: b.waterfront,
  }, since);
  res.json({ ok: true, count: rows.length, label: searchLabel(b),
    sample: rows.slice(0, 5).map(r => ({
      key: r.ListingKey, address: r.UnparsedAddress || '', city: r.City || '',
      price: r.ListPrice || 0, beds: r.BedroomsTotal || 0, baths: r.BathroomsTotalInteger || 0,
    })) });
});

/* The exact email the lead would receive, so the agent sees it before it sends.
   A preview that only lists addresses is not a preview of an email. */
app.post('/api/search/preview-email', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const since = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const rows = await searchRun(b, since);
  const origin = `${req.protocol}://${req.get('host')}`;
  const name = String(b.name || 'there').trim().split(/\s+/)[0] || 'there';
  const label = searchLabel(b);

  const items = rows.slice(0, 6).map(r => ({
    price: r.ListPrice ? '$' + Number(r.ListPrice).toLocaleString() : 'Price on request',
    address: r.UnparsedAddress || 'Address on request',
    city: r.City || '',
    beds: r.BedroomsTotal || null,
    baths: r.BathroomsTotalInteger || null,
    link: `${origin}/?listing=${encodeURIComponent(r.ListingKey || '')}`,
  }));

  res.json({ ok: true, count: rows.length, label,
    subject: rows.length === 1 ? `One new listing \u2014 ${label}`
           : `${rows.length} new listings \u2014 ${label}`,
    greeting: `Hi ${name},`,
    intro: `New since I last wrote, matching ${label}:`,
    items,
    signoff: `Want to see any of them? Just reply.`,
    from: `${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\n${BROKERAGE_ADDRESS}`,
    footer: 'Too many of these, or not enough? Change how often you hear from us, or stop them altogether.',
    /* Said plainly, because the criteria are matched against whatever the MLS
       chose to fill in, and that is not always complete. */
    disclaimer: 'These come straight from the MLS feed. We match your criteria as closely as '
      + 'the data allows, but MLS records are entered by many different offices and are not '
      + 'always complete \u2014 so an occasional listing may not fit, or a good one may be missed. '
      + 'Always worth asking us.',
  });
});

/* The lead's own controls. No login — the token in their email is the key. */
app.get('/api/feed/:token', async (req, res) => {
  const ptr = await getSetting('ssTok:' + String(req.params.token || '').replace(/[^a-f0-9]/gi, ''));
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  if (!rec) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true, name: rec.name, pace: rec.pace,
    label: searchLabel(rec.criteria), agentName: rec.agentName, brokerage: BROKERAGE_NAME });
});

app.post('/api/feed/:token', async (req, res) => {
  const ptr = await getSetting('ssTok:' + String(req.params.token || '').replace(/[^a-f0-9]/gi, ''));
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  if (!rec) return res.status(404).json({ error: 'Not found.' });
  const pace = String((req.body || {}).pace || '');
  if (!['instant','daily','weekly','paused'].includes(pace)) {
    return res.status(400).json({ error: 'Unknown setting.' });
  }
  rec.pace = pace;
  await setSetting(ptr.key, rec);
  console.log(`[search] ${rec.email} set their own pace to ${pace}`);
  res.json({ ok: true, pace });
});

/* ---------- follow-up sequences ----------
   There is no cron on this host, so due steps are processed whenever a signed-in
   agent loads the CRM. Agents log in daily, which is accurate enough for a
   follow-up measured in days — and it means nothing runs for a brokerage that has
   stopped using the system.

   ⚠ EMAIL ONLY, AND NEVER AUTOMATED TEXTS. CAN-SPAM governs commercial email and
   is satisfiable: a real address, an honest subject, and a working unsubscribe in
   every message. TCPA governs automated texts and requires prior express written
   consent — penalties run to $500–$1,500 per message. A "text" step here creates a
   reminder for the agent to send one themselves, which is a different thing in law
   and in tone. */
/* ---------- lanes: which plan a lead belongs on right now ----------
   Two rules from the broker, and they drive everything here:
     1. Nobody ever drops. Silence moves a lead to long-term nurture, it does
        not end them. Only an agent or an opt-out takes a lead out.
     2. Automation never stops on its own. Going hot switches the plan, it does
        not halt it.

   What decides the lane is the RATE of engagement, not the count. Five opens in
   two days is someone shopping this week; five opens over three months is
   someone daydreaming. Re-engagement after a gap is the strongest signal in the
   business — something changed in their life — so it always jumps to the front.

   ⚠ One exception written in deliberately. When a person actually replies, the
   lead moves to 'conversation': alerts keep running and the agent gets a task,
   but no automated email goes out while a human is mid-conversation. That still
   honors "nothing ever stops" — the lead stays on a plan and keeps receiving
   listings — without the CRM talking over the agent. */
const LANES = {
  fast:         { label: 'Moving now',        pace: 1 },
  steady:       { label: 'Normal follow-up',  pace: 1 },
  slow:         { label: 'Long-term nurture', pace: 4 },
  closing:      { label: 'Ready to buy',      pace: 1 },
  conversation: { label: 'Agent is talking',  pace: 0 },
};
const DAY = 86400000;

function laneDecide(lead, now) {
  const ev = Array.isArray(lead.events) ? lead.events : [];
  const at = e => new Date(e.at).getTime();
  const since = ms => ev.filter(e => now - at(e) <= ms);
  const last = ev.length ? Math.max(...ev.map(at)) : new Date(lead.createdAt || now).getTime();
  const quietDays = Math.floor((now - last) / DAY);

  // a person is talking — the agent owns it from here
  if (ev.some(e => ['sms_reply','email_reply','showing_request','agent_call_req'].includes(e.k)
      && now - at(e) <= 14 * DAY)) {
    return { lane: 'conversation', why: 'they replied — leaving the talking to you' };
  }

  // score crossed into hot: switch the plan, do not halt it
  if ((lead.score || 0) >= 70) {
    return { lane: 'closing', why: 'score is hot — moved to the closing plan' };
  }

  /* Back after going quiet. Checked before the compression test because it is
     worth more: three weeks of nothing then two opens means something changed. */
  const recent = since(3 * DAY);
  const older = ev.filter(e => now - at(e) > 21 * DAY);
  if (recent.length >= 2 && older.length && ev.every(e =>
        now - at(e) <= 3 * DAY || now - at(e) > 21 * DAY)) {
    return { lane: 'fast', why: 'went quiet for weeks, then came back — worth a call today' };
  }

  // compressed activity: shopping right now
  if (since(3 * DAY).length >= 3) {
    return { lane: 'fast', why: 'three things in three days — actively looking' };
  }

  /* Silence at 30 days goes to nurture, never to nothing. On this coast a lead
     who goes quiet in June and reappears in September is a snowbird, not a dead
     lead, and the rule above will pick them straight back up. */
  if (quietDays >= 30) {
    return { lane: 'slow', why: quietDays + ' days quiet — moved to long-term nurture' };
  }

  // diffuse interest: engaged, but in no hurry
  if (since(60 * DAY).length >= 4 && since(14 * DAY).length <= 1) {
    return { lane: 'slow', why: 'interested but in no hurry — slowed the pace' };
  }

  return { lane: 'steady', why: '' };
}

/* Sellers are not slow buyers. A valuation request followed by silence usually
   means they are interviewing agents, not that they have gone cold, and a
   buyer-paced cadence at them reads as desperate. */
function lanePace(lead, lane) {
  const base = (LANES[lane] || LANES.steady).pace;
  const isSeller = /seller|valuation|home worth/i.test(
    String(lead.source || '') + ' ' + String(lead.type || ''));
  return isSeller && lane !== 'conversation' ? Math.max(base, 2) : base;
}

/* Every move is written on the lead with its reason, so an agent asking "why is
   she on a different plan?" gets an answer, and so the rules can be judged on
   real leads before they run on a hundred of them. */
function laneApply(lead, now) {
  const d = laneDecide(lead, now);
  const cur = lead.lane || 'steady';
  if (d.lane === cur) return false;
  if (lead.laneLocked) return false;          // an agent set this by hand
  lead.lane = d.lane;
  lead.laneLog = Array.isArray(lead.laneLog) ? lead.laneLog : [];
  lead.laneLog.unshift({ from: cur, to: d.lane, why: d.why, at: new Date(now).toISOString() });
  lead.laneLog = lead.laneLog.slice(0, 40);
  console.log(`[lane] ${lead.name || lead.id}: ${cur} \u2192 ${d.lane} (${d.why})`);
  return true;
}

function dripDue(lead, campaign, now){
  if (!lead.drip || lead.drip.stopped || lead.unsubscribed) return [];
  const lane = lead.lane || 'steady';
  // the agent is mid-conversation: alerts keep running, canned email does not
  if (lane === 'conversation') return [];
  const started = new Date(lead.drip.startedAt || lead.createdAt).getTime();
  const pace = lanePace(lead, lane) || 1;
  // a slower lane stretches the same steps out rather than dropping any of them
  const days = Math.floor((now - started) / (DAY * pace));
  const done = lead.drip.done || [];
  return (campaign.steps || [])
    .filter(st => st.day <= days && !done.includes(st.id));
}

/* ================= CONTENT LIBRARY & BROADCAST =================
   The difference between an agent remembering to nurture forty people and the
   system doing it for four hundred.

   Three parts, and the third is the one that pays for the other two:
     1. Articles live in settings:articles. Written once, sent to a segment.
     2. A broadcast goes to a chosen slice of leads, not to everybody by default.
     3. Every link is tracked, and a click writes a scoring event on the lead.
        That is what makes this more than a newsletter: a click feeds the same
        event log the lanes read, so somebody who reads three pieces in a week
        moves to the fast lane and surfaces on the agent's list by themselves.

   ⚠ CAN-SPAM applies to every one of these. Physical address, honest subject and
   a working unsubscribe in each send — all three are built in below, not left to
   whoever writes the article. */

const ARTICLES_KEY = 'settings:articles';
const BROADCAST_LOG = 'settings:broadcasts';
const SEND_CHUNK = 25;              // Resend does not love 400 at once
const SEND_PAUSE = 1100;            // ms between chunks

function clickToken(leadId, artId) {
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('click:' + leadId + ':' + artId).digest('hex').slice(0, 20);
}

/* Who a broadcast actually goes to. Deliberately explicit: an agent can only
   reach their own people, and "everyone" has to be asked for by name. */
function segmentLeads(all, seg, sess) {
  const staff = isStaff(sess);
  return all.filter(({ lead }) => {
    if (!lead.email || lead.unsubscribed) return false;
    if (!staff && lead.assignedAgentId !== sess.agentId) return false;
    if (seg.agentId && lead.assignedAgentId !== seg.agentId) return false;
    if (seg.lane && (lead.lane || 'steady') !== seg.lane) return false;
    if (seg.stage && lead.stage !== seg.stage) return false;
    if (seg.type && String(lead.type || '') !== seg.type) return false;
    if (seg.minScore && (lead.score || 0) < Number(seg.minScore)) return false;
    return true;
  });
}

app.get('/api/articles', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const saved = await getSetting(ARTICLES_KEY);
  res.json({ ok: true, articles: Array.isArray(saved) ? saved : [] });
});

app.post('/api/articles', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });
  const list = Array.isArray((req.body || {}).articles) ? req.body.articles : null;
  if (!list) return res.status(400).json({ error: 'Send an articles array.' });
  const clean = list.slice(0, 200).map(a => ({
    id: String(a.id || 'art_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
    title: String(a.title || '').slice(0, 160),
    teaser: String(a.teaser || '').slice(0, 500),
    body: String(a.body || '').slice(0, 20000),
    url: String(a.url || '').slice(0, 400),
    image: String(a.image || '').slice(0, 400),
    updatedAt: new Date().toISOString(),
  })).filter(a => a.title);
  await setSetting(ARTICLES_KEY, clean);
  res.json({ ok: true, articles: clean });
});

/* A click is the whole point. It redirects, and on the way it writes the event
   that the score and the lane engine both read. */
app.get('/c/:leadId/:artId/:tok', async (req, res) => {
  const { leadId, artId, tok } = req.params;
  const fallback = '/';
  if (tok !== clickToken(leadId, artId)) return res.redirect(fallback);
  let dest = fallback;
  try {
    const arts = await getSetting(ARTICLES_KEY);
    const art = (Array.isArray(arts) ? arts : []).find(a => a.id === artId);
    const who = String(req.query.a || '').slice(0, 60).replace(/[^a-z0-9-]/gi, '');
    if (art) dest = art.url && /^https?:/.test(art.url)
      ? art.url
      : `${req.protocol}://${req.get('host')}/insights/${articleSlug(art)}`
        + (who ? `?agent=${encodeURIComponent(who)}` : '');

    const key = 'lead:' + leadId;
    const lead = await getSetting(key);
    if (lead) {
      lead.events = Array.isArray(lead.events) ? lead.events : [];
      lead.events.push({ k: 'article_click', at: new Date().toISOString(),
        note: (art && art.title || '').slice(0, 120) });
      lead.lastActivity = new Date().toISOString();
      const { score, band } = leadScore(lead);
      lead.score = score; lead.band = band.key;
      try { laneApply(lead, Date.now()); } catch (e) {}
      await setSetting(key, lead);
      console.log(`[click] ${lead.name || leadId} opened "${art && art.title || artId}"`);
    }
  } catch (e) { console.error('[click]', e.message); }
  res.redirect(dest);
});

app.post('/api/broadcast', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const seg = b.segment || {};
  const ids = Array.isArray(b.articleIds) ? b.articleIds.slice(0, 6) : [];
  const subject = String(b.subject || '').trim().slice(0, 160);
  const intro = String(b.intro || '').trim().slice(0, 1200);
  const dryRun = b.dryRun !== false;      // ⚠ default is DRY. Sending 400 emails by accident is unrecoverable.

  if (!subject) return res.status(400).json({ error: 'A subject line, at least.' });
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one article.' });

  let arts = await getSetting(ARTICLES_KEY);
  arts = (Array.isArray(arts) ? arts : []).filter(a => ids.includes(a.id));
  if (!arts.length) return res.status(400).json({ error: 'Those articles no longer exist.' });

  let all = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    all = (data || []).map(r => ({ key: r.key, lead: r.value })).filter(x => x.lead);
  } catch (e) { return res.status(500).json({ error: 'Could not read leads.' }); }

  const recipients = segmentLeads(all, seg, sess);
  if (dryRun) {
    return res.json({ ok: true, dryRun: true, wouldSend: recipients.length,
      sample: recipients.slice(0, 5).map(r => r.lead.email) });
  }
  if (!mailer) return res.status(400).json({ error: 'Email is not configured.' });

  const origin = `${req.protocol}://${req.get('host')}`;
  const senderSlug = slugify(sess.name || '');
  const bid = 'bc_' + Date.now().toString(36);
  let sent = 0, failed = 0;

  for (let i = 0; i < recipients.length; i += SEND_CHUNK) {
    const chunk = recipients.slice(i, i + SEND_CHUNK);
    await Promise.all(chunk.map(async ({ key, lead }) => {
      const first = String(lead.name || '').trim().split(/\s+/)[0] || 'there';
      const items = arts.map(a => {
        // ?a= is the sending agent, so a lead from this email lands on them
        const link = `${origin}/c/${lead.id}/${a.id}/${clickToken(lead.id, a.id)}`
          + (senderSlug ? `?a=${encodeURIComponent(senderSlug)}` : '');
        return `${a.title}\n${a.teaser}\n${link}`;
      }).join('\n\n');
      const unsub = `${origin}/?unsub=${lead.id}.${unsubToken(lead.id)}`;
      try {
        await mailer.sendMail({
          to: lead.email,
          marketing: true,
          subject,
          text: `Hi ${first},\n\n${intro ? intro + '\n\n' : ''}${items}\n\n`
              + `\u2014\n${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\n`
              + `${BROKERAGE_ADDRESS}\n\nNo longer want these? ${unsub}`,
        });
        sent++;
        lead.broadcasts = Array.isArray(lead.broadcasts) ? lead.broadcasts : [];
        lead.broadcasts.unshift({ id: bid, subject, at: new Date().toISOString() });
        lead.broadcasts = lead.broadcasts.slice(0, 30);
        await setSetting(key, lead);
      } catch (e) { failed++; console.error('[broadcast]', lead.email, e.message); }
    }));
    if (i + SEND_CHUNK < recipients.length) {
      await new Promise(r => setTimeout(r, SEND_PAUSE));
    }
  }

  try {
    const log = await getSetting(BROADCAST_LOG);
    const arr = Array.isArray(log) ? log : [];
    arr.unshift({ id: bid, subject, articleIds: ids, segment: seg,
      sent, failed, by: sess.name || sess.agentId, at: new Date().toISOString() });
    await setSetting(BROADCAST_LOG, arr.slice(0, 100));
  } catch (e) {}

  console.log(`[broadcast] "${subject}" \u2014 ${sent} sent, ${failed} failed`);
  res.json({ ok: true, sent, failed, broadcastId: bid });
});

app.get('/api/broadcasts', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });
  const log = await getSetting(BROADCAST_LOG);
  res.json({ ok: true, broadcasts: Array.isArray(log) ? log : [] });
});

function unsubToken(leadId){
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('unsub:' + leadId).digest('hex').slice(0, 24);
}

function dripFill(text, lead, agent){
  const first = String(lead.name || '').trim().split(/\s+/)[0] || 'there';
  return String(text || '')
    .replace(/\{first\}/g, first)
    .replace(/\{name\}/g, lead.name || '')
    .replace(/\{agent\}/g, agent.name || '')
    .replace(/\{brokerage\}/g, BROKERAGE_NAME)
    .replace(/\{phone\}/g, BROKERAGE_PHONE)
    .replace(/\{address\}/g, lead.listingLabel || 'the property');
}

/* Called when the CRM loads. Sends what is due, records what was sent. */
app.post('/api/drip/tick', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const campaigns = (await getSetting('settings:dripCampaigns')) || [];
  if (!Array.isArray(campaigns) || !campaigns.length) return res.json({ ok: true, sent: 0 });

  const now = Date.now();
  const origin = `${req.protocol}://${req.get('host')}`;
  let sent = 0, tasks = [];

  let leads = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    leads = (data || []).map(r => ({ key: r.key, lead: r.value })).filter(x => x.lead);
  } catch (e) { return res.status(500).json({ error: 'Could not read leads.' }); }

  for (const { key, lead } of leads) {
    if (!isStaff(sess) && lead.assignedAgentId !== sess.agentId) continue;
    if (!lead.drip || !lead.drip.campaignId) continue;
    const camp = campaigns.find(c => c.id === lead.drip.campaignId);
    if (!camp || camp.paused) continue;

    // the sweep is the only thing that runs regularly, so lanes are judged here
    let changed = false;
    try { if (laneApply(lead, now)) changed = true; } catch (e) {}

    const due = dripDue(lead, camp, now);
    if (!due.length) { if (changed) await setSetting(key, lead); continue; }

    for (const step of due) {
      if (step.type === 'email') {
        if (!lead.email || !mailer) { continue; }
        const unsub = `${origin}/?unsub=${lead.id}.${unsubToken(lead.id)}`;
        try {
          await mailer.sendMail({
            to: lead.email,
            subject: dripFill(step.subject, lead, sess),
            text: dripFill(step.body, lead, sess)
                + `\n\n\u2014\n${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}`
                + `\n${BROKERAGE_ADDRESS}`
                + `\n\nIf you would rather not hear from us, unsubscribe here: ${unsub}`,
          });
          sent++;
        } catch (e) { console.error('[drip] send failed:', e.message); continue; }
      } else {
        // a reminder for the agent, not an automated message
        tasks.push({ leadId: lead.id, name: lead.name, what: step.subject });
      }
      lead.drip.done = (lead.drip.done || []).concat(step.id);
      lead.drip.lastAt = new Date().toISOString();
      changed = true;
    }
    if (changed) { try { await setSetting(key, lead); } catch (e) {} }
  }
  /* Saved searches, same pass. A listing is never sent twice, and the pace the
     lead chose is honored — including "paused", which they can set themselves. */
  let feeds = 0;
  const GAP = { instant: 0, daily: 20 * 3600000, weekly: 6.5 * 86400000 };
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value')
      .ilike('key', 'savedSearch:' + (isStaff(sess) ? '%' : sess.agentId + ':%'));
    for (const row of (data || [])) {
      const rec = row.value;
      if (!rec || rec.pace === 'paused' || !rec.email) continue;
      const since = new Date(rec.lastSent || rec.createdAt).getTime();
      if (Date.now() - since < (GAP[rec.pace] ?? GAP.daily)) continue;

      const day = new Date(rec.lastSent || rec.createdAt).toISOString().slice(0, 10);
      const rows = await searchRun(rec.criteria || {}, day);
      const seen = rec.sentKeys || [];
      const fresh = rows.filter(r => r.ListingKey && !seen.includes(r.ListingKey));
      if (!fresh.length) { rec.lastSent = new Date().toISOString(); await setSetting(row.key, rec); continue; }

      if (mailer) {
        const link = `${origin}/?feed=${searchToken(rec.id)}`;
        const lines = fresh.slice(0, 8).map(r => {
          const price = r.ListPrice ? '$' + Number(r.ListPrice).toLocaleString() : 'Price on request';
          const bb = [r.BedroomsTotal ? r.BedroomsTotal + ' bed' : '',
                      r.BathroomsTotalInteger ? r.BathroomsTotalInteger + ' bath' : '']
                      .filter(Boolean).join(', ');
          return `  ${price} \u2014 ${r.UnparsedAddress || 'Address on request'}`
               + (r.City ? `, ${r.City}` : '') + (bb ? `\n    ${bb}` : '')
               + `\n    ${origin}/?listing=${encodeURIComponent(r.ListingKey)}`;
        }).join('\n\n');
        try {
          await mailer.sendMail({
            to: rec.email,
            subject: fresh.length === 1
              ? `One new listing \u2014 ${searchLabel(rec.criteria)}`
              : `${fresh.length} new listings \u2014 ${searchLabel(rec.criteria)}`,
            text: `Hi ${String(rec.name || '').split(' ')[0] || 'there'},\n\n`
                + `New since I last wrote, matching ${searchLabel(rec.criteria)}:\n\n${lines}\n\n`
                + `Want to see any of them? Just reply.\n\n`
                + `${rec.agentName}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\n${BROKERAGE_ADDRESS}\n\n`
                + `Too many of these, or not enough? Change how often you hear from us, `
                + `or stop them altogether: ${link}`,
          });
          feeds++;
        } catch (e) { console.error('[search] send failed:', e.message); }
      }
      rec.sentKeys = seen.concat(fresh.map(r => r.ListingKey)).slice(-400);
      rec.lastSent = new Date().toISOString();
      await setSetting(row.key, rec);
    }
  } catch (e) { console.error('[search] pass failed:', e.message); }

  if (sent || feeds) console.log(`[drip] ${sent} follow-up(s), ${feeds} listing alert(s) for ${sess.name}`);
  res.json({ ok: true, sent, feeds, tasks });
});

/* Unsubscribe. Public, no session, and it must always work — a broken one is the
   thing that turns a complaint into a penalty. */
app.get('/api/unsub/:pair', async (req, res) => {
  const [leadId, token] = String(req.params.pair || '').split('.');
  if (!leadId || token !== unsubToken(leadId)) {
    return res.status(404).json({ error: 'Not found.' });
  }
  const lead = await getSetting('lead:' + leadId);
  if (!lead) return res.status(404).json({ error: 'Not found.' });
  lead.unsubscribed = true;
  lead.unsubscribedAt = new Date().toISOString();
  if (lead.drip) lead.drip.stopped = true;
  await setSetting('lead:' + leadId, lead);
  console.log(`[drip] ${lead.email || leadId} unsubscribed`);
  res.json({ ok: true, email: lead.email || '' });
});

/* ---------- open house sign-in ----------
   A QR on a sign or an iPad. The visitor signs in on their own phone, which is
   faster than a clipboard, legible, and means they have already given you a
   working email rather than one you have to decipher.

   The token is the only secret, so it is long and the public routes return only
   what a visitor needs to see. Sign-ins become leads through the normal path. */
const OH_FEEDBACK = [
  { k:'impression', q:'First impression?',
    a:['Loved it','Liked it','It was fine','Not for me'] },
  { k:'price', q:'How did the price feel?',
    a:['About right','A bit high','Too high','Good value'] },
  { k:'stage', q:'Where are you in your search?',
    a:['Just looking','Looking seriously','Ready to make an offer','Need to sell first'] },
  { k:'agent', q:'Are you working with an agent?',
    a:['No, not yet','Yes, I have one'] },
];

app.post('/api/openhouse', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const clean = v => String(v == null ? '' : v).slice(0, 200).trim();
  const id = 'oh_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  const token = crypto.randomBytes(16).toString('hex');
  const rec = {
    id, token,
    agentId: sess.agentId, agentName: sess.name || '', agentEmail: sess.email || '',
    address: clean(b.address), listingKey: clean(b.listingKey),
    price: clean(b.price), when: clean(b.when),
    visitors: [], feedbackSent: false,
    createdAt: new Date().toISOString(),
  };
  await setSetting('openHouse:' + sess.agentId + ':' + id, rec);
  await setSetting('ohTok:' + token, { key: 'openHouse:' + sess.agentId + ':' + id });
  console.log(`[openhouse] ${sess.name} opened ${rec.address || 'a house'}`);
  res.json({ ok: true, openHouse: rec });
});

app.get('/api/openhouse/mine', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const out = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value')
      .ilike('key', 'openHouse:' + sess.agentId + ':%');
    (data || []).forEach(r => { if (r.value) out.push(r.value); });
  } catch (e) { console.error('[openhouse] list failed:', e.message); }
  out.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  res.json({ ok: true, openHouses: out });
});

app.delete('/api/openhouse/:id', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'openHouse:' + sess.agentId + ':' + String(req.params.id || '');
  const rec = await getSetting(key);
  if (rec && rec.token) {
    try { await supabase.from(KV_TABLE).delete().eq('key', 'ohTok:' + rec.token); } catch (e) {}
  }
  try { await supabase.from(KV_TABLE).delete().eq('key', key); } catch (e) {}
  res.json({ ok: true });
});

/* What the visitor's phone loads. No session. */
app.get('/api/oh/:token', async (req, res) => {
  const token = String(req.params.token || '').replace(/[^a-f0-9]/gi, '');
  if (token.length < 20) return res.status(404).json({ error: 'Not found.' });
  const ptr = await getSetting('ohTok:' + token);
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  if (!rec) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true, openHouse: {
    address: rec.address || '', price: rec.price || '', when: rec.when || '',
    agentName: rec.agentName || '', brokerage: BROKERAGE_NAME,
  }});
});

app.post('/api/oh/:token/signin', async (req, res) => {
  if (!requireSupabase(res)) return;
  const token = String(req.params.token || '').replace(/[^a-f0-9]/gi, '');
  const ptr = await getSetting('ohTok:' + token);
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  if (!rec) return res.status(404).json({ error: 'Not found.' });

  const b = req.body || {};
  const clean = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  const name = clean(b.name, 80);
  const email = clean(b.email, 120);
  if (!name) return res.status(400).json({ error: 'A name, at least.' });

  const visitor = {
    id: 'v_' + Date.now().toString(36) + '_' + crypto.randomBytes(2).toString('hex'),
    name, email, phone: clean(b.phone, 40),
    hasAgent: !!b.hasAgent,
    at: new Date().toISOString(),
    feedback: null,
  };
  rec.visitors = Array.isArray(rec.visitors) ? rec.visitors : [];
  rec.visitors.push(visitor);
  await setSetting(ptr.key, rec);

  /* Anyone already working with an agent is recorded but not turned into a lead \u2014
     chasing another agent's client is how you end up in front of the association. */
  if (!visitor.hasAgent && email) {
    const lead = {
      id: 'lead_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      name, email, phone: visitor.phone,
      message: 'Signed in at the open house' + (rec.address ? ' at ' + rec.address : '') + '.',
      source: 'open-house',
      mlsKey: rec.listingKey || '', listingLabel: rec.address || '',
      stage: 'New', notes: '',
      assignedAgentId: rec.agentId,
      createdAt: new Date().toISOString(),
    };
    try {
      await setSetting('lead:' + lead.id, lead);
      console.log(`[openhouse] ${name} signed in \u2014 lead created for ${rec.agentName}`);
    } catch (e) { console.error('[openhouse] lead failed:', e.message); }
  }
  res.json({ ok: true, visitorId: visitor.id });
});

/* The follow-up: four checkbox questions, which is why people answer them. */
app.post('/api/openhouse/:id/feedback', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const key = 'openHouse:' + sess.agentId + ':' + String(req.params.id || '');
  const rec = await getSetting(key);
  if (!rec) return res.status(404).json({ error: 'Not found.' });
  if (!mailer) return res.status(503).json({ error: 'Email is not set up.' });

  const origin = `${req.protocol}://${req.get('host')}`;
  let sent = 0;
  for (const v of (rec.visitors || [])) {
    if (!v.email || v.feedback) continue;
    const link = `${origin}/?ohf=${rec.token}.${v.id}`;
    try {
      await mailer.sendMail({
        to: v.email,
        subject: `Thanks for coming by${rec.address ? ' \u2014 ' + rec.address : ''}`,
        text: `Hi ${String(v.name).split(' ')[0]},\n\n`
            + `Thanks for stopping by${rec.address ? ' ' + rec.address : ''} today.\n\n`
            + `Four quick questions, all checkboxes \u2014 it takes about ten seconds and it `
            + `genuinely helps:\n${link}\n\n`
            + `And if you'd like to see it again, or see something else, just reply.\n\n`
            + `${rec.agentName}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}`,
      });
      sent++;
    } catch (e) { console.error('[openhouse] feedback email failed:', e.message); }
  }
  rec.feedbackSent = true;
  await setSetting(key, rec);
  console.log(`[openhouse] ${sess.name} asked ${sent} visitor(s) for feedback`);
  res.json({ ok: true, sent });
});

app.get('/api/ohf/:pair', async (req, res) => {
  const [token, vid] = String(req.params.pair || '').split('.');
  const t = String(token || '').replace(/[^a-f0-9]/gi, '');
  if (t.length < 20) return res.status(404).json({ error: 'Not found.' });
  const ptr = await getSetting('ohTok:' + t);
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  const v = (rec && rec.visitors || []).find(x => x.id === vid);
  if (!rec || !v) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true,
    address: rec.address || '', agentName: rec.agentName || '',
    brokerage: BROKERAGE_NAME, firstName: String(v.name || '').split(' ')[0],
    already: !!v.feedback, questions: OH_FEEDBACK });
});

app.post('/api/ohf/:pair', async (req, res) => {
  const [token, vid] = String(req.params.pair || '').split('.');
  const t = String(token || '').replace(/[^a-f0-9]/gi, '');
  const ptr = await getSetting('ohTok:' + t);
  if (!ptr || !ptr.key) return res.status(404).json({ error: 'Not found.' });
  const rec = await getSetting(ptr.key);
  const v = (rec && rec.visitors || []).find(x => x.id === vid);
  if (!rec || !v) return res.status(404).json({ error: 'Not found.' });

  const answers = {};
  OH_FEEDBACK.forEach(q => {
    const a = String((req.body || {})[q.k] || '').slice(0, 60);
    if (q.a.includes(a)) answers[q.k] = a;
  });
  answers.note = String((req.body || {}).note || '').slice(0, 600);
  v.feedback = Object.assign({ at: new Date().toISOString() }, answers);
  await setSetting(ptr.key, rec);

  if (mailer && rec.agentEmail) {
    const lines = OH_FEEDBACK.filter(q => answers[q.k])
      .map(q => `  ${q.q}  ${answers[q.k]}`).join('\n');
    mailer.sendMail({
      to: rec.agentEmail,
      subject: `Feedback from ${v.name}${rec.address ? ' \u2014 ' + rec.address : ''}`,
      text: `${v.name} answered your open house questions.\n\n${lines}`
          + (answers.note ? `\n\n  "${answers.note}"` : '')
          + `\n\n${BROKERAGE_NAME}`,
    }).catch(e => console.error('[openhouse] notify failed:', e.message));
  }
  res.json({ ok: true });
});

/* ---------- public review submission ----------
   A visitor has no session, and public writes are limited to lead: keys — so the
   review form was posting straight into a 401 and the visitor was thanked for a
   review nobody ever received. Rather than opening up public writes to a settings
   key, reviews come through here: validated, forced to pending, and the broker is
   told about it. */
app.post('/api/review', async (req, res) => {
  if (!requireSupabase(res)) return;
  const b = req.body || {};
  const author = String(b.author || '').trim().slice(0, 80);
  const text   = String(b.text || '').trim().slice(0, 2000);
  const rating = Math.max(1, Math.min(5, parseInt(b.rating, 10) || 5));
  const agentId = String(b.agentId || '').trim().slice(0, 60);

  if (!author || !text) return res.status(400).json({ error: 'A name and a few words, please.' });
  if (text.length < 4) return res.status(400).json({ error: 'Tell us a little more.' });

  const review = {
    id: 'rv_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
    author, text, rating, agentId,
    status: 'pending',                       // never public until the broker clears it
    submittedAt: new Date().toISOString(),
  };

  try {
    const list = (await getSetting('settings:testimonials')) || [];
    const arr = Array.isArray(list) ? list : [];
    // light flood guard: same name and text within the hour is a double submit
    const hourAgo = Date.now() - 3600000;
    const dupe = arr.some(r => r.author === author && r.text === text &&
                          new Date(r.submittedAt || 0).getTime() > hourAgo);
    if (dupe) return res.json({ ok: true, duplicate: true });

    arr.push(review);
    await setSetting('settings:testimonials', arr);
    console.log(`[review] ${author} left a ${rating}-star review${agentId ? ' for ' + agentId : ''}`);
  } catch (e) {
    console.error('[review] save failed:', e.message);
    return res.status(500).json({ error: 'Could not save that just now.' });
  }

  // tell the broker, and the agent it was about
  if (mailer) {
    const stars = '\u2605'.repeat(rating) + '\u2606'.repeat(5 - rating);
    const to = [];
    try {
      const notify = await resolveNotifyAddress();
      if (notify) to.push(notify);
      if (agentId) {
        const { data: ag } = await supabase.from('agents')
          .select('email,active').eq('id', agentId).maybeSingle();
        if (ag && ag.email && ag.active !== false && !to.includes(ag.email)) to.push(ag.email);
      }
    } catch (e) {}
    for (const addr of to) {
      mailer.sendMail({
        to: addr,
        subject: `New review from ${author} — ${rating} star${rating === 1 ? '' : 's'}`,
        text: `${author} left a review on bamacoast.com.\n\n${stars}\n\n"${text}"\n\n`
            + `It is waiting for approval and is not showing publicly yet.\n`
            + `Approve or decline it under Reviews in the CRM.\n\n${BROKERAGE_NAME}`,
      }).then(() => console.log(`[review] notified ${addr}`))
        .catch(e => console.error('[review] notify failed:', e.message));
    }
  } else {
    console.warn('[review] SKIPPED notification — mailer not configured.');
  }

  res.json({ ok: true });
});

/* ---------- ideas from the people using this every day ----------
   One button in the CRM, straight to the broker. Deliberately its own route
   rather than a kv key an agent may write: settings:ideas is not in
   AGENT_READABLE, so agents cannot read each other's notes or edit the list —
   they can only add through here and read their own back through /api/ideas.
   The same reasoning as the public review form, one step further in. */
const IDEAS_KEY = 'settings:ideas';
const IDEAS_MAX = 500;          // oldest fall off; the list cannot grow without bound
const IDEA_MAX_CHARS = 2000;

app.post('/api/idea', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await getSession(req);
  if (!sess) return res.status(401).json({ error: 'Sign in to send an idea.' });

  const b = req.body || {};
  const text = String(b.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Write something first.' });
  if (text.length > IDEA_MAX_CHARS) {
    return res.status(400).json({ error: `Keep it under ${IDEA_MAX_CHARS} characters.` });
  }
  const area = String(b.area || '').trim().slice(0, 60);

  // Who sent it, resolved server-side. An agent cannot put someone else's name on it.
  let who = sess.agentId;
  try {
    const { data } = await supabase.from('agents').select('name').eq('id', sess.agentId).maybeSingle();
    if (data && data.name) who = data.name;
  } catch (e) { /* fall back to the id — never block the save on a lookup */ }

  const idea = {
    id: 'i_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    agentId: sess.agentId,
    agentName: who,
    area,
    text,
    at: new Date().toISOString(),
    read: false,
    archived: false,
  };

  /* Save first, notify second. The review form taught us this the hard way:
     thanking someone for something that was never stored is worse than an
     error message. If the email fails the idea is still safely on the list. */
  try {
    const { data } = await supabase.from(KV_TABLE).select('value').eq('key', IDEAS_KEY).maybeSingle();
    const list = Array.isArray(data && data.value) ? data.value : [];
    list.unshift(idea);
    const trimmed = list.slice(0, IDEAS_MAX);
    const { error } = await supabase.from(KV_TABLE)
      .upsert({ key: IDEAS_KEY, value: trimmed }, { onConflict: 'key' });
    if (error) throw new Error(error.message);
    console.log(`[idea] saved from ${who}${area ? ' about ' + area : ''}`);
  } catch (e) {
    console.error('[idea] save failed:', e.message);
    return res.status(500).json({ error: 'Could not save that. Please try again.' });
  }

  if (mailer) {
    const addr = await resolveNotifyAddress();
    if (addr) {
      mailer.sendMail({
        to: addr,
        subject: `Idea from ${who}${area ? ' — ' + area : ''}`,
        text: `${who} sent this from the CRM${area ? `, about ${area}` : ''}:\n\n${text}\n\n`
            + `It is on the list under Settings \u2192 Ideas from your agents.\n${BROKERAGE_NAME}`,
      }).then(() => console.log(`[idea] notified ${addr}`))
        .catch(e => console.error('[idea] notify failed:', e.message));
    } else {
      console.error('[idea] no destination address — set NOTIFY_EMAIL or make sure a broker exists.');
    }
  } else {
    console.warn('[idea] SKIPPED notification — mailer not configured.');
  }

  res.json({ ok: true, idea });
});

/* Staff see every idea. An agent sees only their own, so the button feels like
   it goes somewhere rather than into a void — without turning the list into a
   place where agents read each other's complaints. */
app.get('/api/ideas', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await getSession(req);
  if (!sess) return res.status(401).json({ error: 'Sign in to see these.' });
  try {
    const { data } = await supabase.from(KV_TABLE).select('value').eq('key', IDEAS_KEY).maybeSingle();
    const list = Array.isArray(data && data.value) ? data.value : [];
    res.json({ ideas: isStaff(sess) ? list : list.filter(i => i && i.agentId === sess.agentId) });
  } catch (e) {
    console.error('[GET /api/ideas] failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ---------- client password reset ----------
   Agents have reset_token / reset_expires columns; the clients table does not,
   and adding columns by hand in Supabase is a step that is easy to get wrong.
   Tokens live in kv_store instead as clientReset:<token> — no schema change,
   and they are deleted the moment they are used.

   The reply is deliberately identical whether or not the email has an account,
   so this cannot be used to discover which addresses are registered.         */
app.post('/api/client/forgot-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const generic = { ok: true, message: 'If that email has an account, a reset link is on its way.' };
  if (!email) return res.json(generic);
  try {
    const { data } = await supabase.from('clients').select('id,name,email').eq('email', email).maybeSingle();
    if (data) {
      const token = crypto.randomBytes(24).toString('hex');
      await setSetting('clientReset:' + token, {
        clientId: data.id,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),   // 1 hour
      });
      if (mailer) {
        const link = `${req.protocol}://${req.get('host')}/?creset=${token}`;
        const first = String(data.name || '').trim().split(/\s+/)[0] || 'there';
        await mailer.sendMail({
          to: data.email,
          subject: `Reset your ${BROKERAGE_NAME} password`,
          text: `Hi ${first},

Someone asked to reset the password on your bamacoast.com account. If that was you,
set a new one here — the link works for one hour:

${link}

If it wasn't you, nothing has changed and you can ignore this.

${BROKERAGE_NAME}
${BROKERAGE_PHONE}
bamacoast.com`,
        }).catch(e => console.error('[client reset email] failed:', e.message));
        console.log(`[client reset] link sent to ${data.email}`);
      } else {
        console.warn('[client reset] SKIPPED — mailer not configured.');
      }
    } else {
      console.log('[client reset] request for an address with no account');
    }
  } catch (e) { console.error('[client reset] failed:', e.message); }
  res.json(generic);
});

app.post('/api/client/reset-password', async (req, res) => {
  if (!requireSupabase(res)) return;
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  try {
    const rec = await getSetting('clientReset:' + token);
    if (!rec || !rec.clientId)
      return res.status(400).json({ error: 'This link is not valid, or it has already been used.' });
    if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) {
      await supabase.from('kv_store').delete().eq('key', 'clientReset:' + token);
      return res.status(400).json({ error: 'This link has expired — please request a new one.' });
    }
    const { data: client } = await supabase.from('clients')
      .select('id,name,email').eq('id', rec.clientId).maybeSingle();
    if (!client) return res.status(400).json({ error: 'That account no longer exists.' });

    await supabase.from('clients')
      .update({ password_hash: hashPassword(String(password)) }).eq('id', client.id);
    // single use
    await supabase.from('kv_store').delete().eq('key', 'clientReset:' + token);
    console.log(`[client reset] password changed for ${client.email}`);

    // sign them straight in rather than making them type it again
    const sessToken = await createClientSession(client.id);
    const { data: full } = await supabase.from('clients').select('*').eq('id', client.id).maybeSingle();
    res.json({ ok: true, token: sessToken, client: full ? clientPublic(full) : null });
  } catch (e) {
    console.error('[client reset] failed:', e.message);
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

/* ---------- backend safety for anything the AI says ----------
   The system prompt tells the model what not to do. This layer assumes the model
   might do it anyway, and checks both what came in and what went out. Two
   independent guards, because a prompt is guidance and this is a rule.

   \u26a0 FAIR HOUSING. Steering does not require intent. Answering "is this a good
   area for families?" or "what are the schools like?" with anything other than a
   pointer to public data is a violation, and it is the brokerage's license.

   \u26a0 LICENSED ADVICE. Opining on price, contract terms, or what somebody should
   offer is licensed activity in Alabama and Florida. Software is not licensed. */
const FH_TOPICS = [
  /\bschool(s|ing|ed)?\b/i, /\bschool district\b/i,
  /\b(safe|safety|crime|dangerous|sketchy|rough area|bad area)\b/i,
  /\b(race|racial|ethnic|ethnicity|black|white|hispanic|asian|jewish|muslim|christian)\b/i,
  /\b(church|churches|synagogue|synagogues|mosque|mosques|temple|temples|congregation)\b/i,
  /\b(family|families|kids|children|child.friendly|good for kids)\b/i,
  /\b(demographic|who lives|what kind of people|neighbors are|type of people)\b/i,
  /\b(elderly|retirement community|singles|young professionals)\b/i,
  /\b(disabled|disability|handicap)\b/i,
  /\bnational origin\b/i, /\bimmigrant/i,
];
const ADVICE_TOPICS = [
  /\bwhat should i offer\b/i, /\bhow much should i (offer|bid|pay)\b/i,
  /\bis it worth\b/i, /\bwill it appraise\b/i, /\bgood (deal|investment|price)\b/i,
  /\b(contract|contingency|addendum|clause|earnest money) (say|mean|work)/i,
  /\bcan i (back out|cancel|get out of)\b/i,
  /\b(legal|lawyer|attorney|sue|lawsuit|tax|taxes|capital gains|1031)\b/i,
  /\bwhat('| i)?s (it|this|the (house|condo|property)) worth\b/i,
];

function guardTopic(text){
  const t = String(text || '');
  if (FH_TOPICS.some(r => r.test(t))) return 'fairhousing';
  if (ADVICE_TOPICS.some(r => r.test(t))) return 'advice';
  return null;
}

const GUARD_REPLY = {
  fairhousing:
    "That's a good question, and it's one I have to be careful with — fair housing rules mean "
    + "I shouldn't characterize an area or who lives there, and honestly you'd get a better answer "
    + "from the source anyway. School district sites, the census, and local crime statistics are "
    + "all public, and they'll tell you more than my opinion would.\n\n"
    + "What I can help with is the properties themselves. Want me to have "
    + "someone call you about that?",
  advice:
    "That one really does need a licensed person rather than me — it depends on the specific "
    + "property and the contract, and getting it slightly wrong could cost you real money.\n\n"
    + "Let me get one of our agents to call you. What's the best number, and roughly when suits?",
};

/* Every AI message says it is AI, once, at the start of a conversation. */
const AI_DISCLOSURE =
  "Quick note so you know who you're talking to: I'm an automated assistant for "
  + BROKERAGE_NAME + ", not a person. I can answer questions about properties and the area, "
  + "and I'll get a licensed agent to call you for anything that needs one.";

app.post('/api/chat', async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI chat is not configured yet. Set ANTHROPIC_API_KEY in the hosting environment variables.' });
  }
  const { message, history } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message is required' });

  /* Guard 1: what they asked. Caught before the model ever sees it. */
  const asked = guardTopic(message);
  if (asked) {
    console.log(`[chat] ${asked} topic caught on the way in \u2014 handed to an agent`);
    return res.json({ reply: GUARD_REPLY[asked], handoff: true, reason: asked });
  }

  try {
    const messages = [
      ...(Array.isArray(history) ? history.slice(-10) : []),
      { role: 'user', content: message },
    ];
    let reply = await callClaude(CHAT_SYSTEM_PROMPT, messages, 400);

    /* Guard 2: what it answered. The model is well behaved, but this is the
       brokerage's license and a prompt is not a guarantee. */
    const said = guardTopic(reply);
    if (said) {
      console.warn(`[chat] model output tripped the ${said} guard \u2014 replaced`);
      return res.json({ reply: GUARD_REPLY[said], handoff: true, reason: said });
    }

    // first message in a conversation says plainly that it is not a person
    const first = !Array.isArray(history) || history.length === 0;
    if (first) reply = AI_DISCLOSURE + '\n\n' + reply;

    res.json({ reply, disclosed: first });
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
    serverVersion: 'v90',
    routes: ['market-stats','mls-fields','search','listings'],
    brokerage: BROKERAGE_NAME,
    database: !!supabase,
    mlsDataset: process.env.BRIDGE_DATASET || 'gcmls2',
    mlsConfigured: !!(process.env.BRIDGE_SERVER_TOKEN && process.env.BRIDGE_DATASET),
    emailConfigured: !!mailer,
    marketingDomainReady: MARKETING_READY,
    aiConfigured: !!ANTHROPIC_API_KEY,
  });
});

// ---------- Social preview cards for shared listing links ----------
// Sample data, kept only for /api/mock-listings so a demo or a smoke test works
// without the MLS configured. Social cards and the site itself read the live feed.
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

app.get('/', async (req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  const listingKey = req.query.listing;
  if (!listingKey || !CRAWLER_UA_PATTERN.test(ua)) return next(); // normal visitors -> fall through to the SPA

  // This read MOCK_LISTINGS, so sharing a real listing produced no card at all
  // and the nine fake ones showed invented prices. It uses the live feed now.
  let listing = null;
  try {
    const token = process.env.BRIDGE_SERVER_TOKEN, dataset = process.env.BRIDGE_DATASET;
    if (token && dataset) {
      const key = String(listingKey).slice(0, 128).replace(/'/g, "''");
      const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
        + `?access_token=${encodeURIComponent(token)}`
        + `&$filter=${encodeURIComponent(`ListingKey eq '${key}'`)}&$top=1`;
      const r = await fetch(url);
      if (r.ok) listing = ((await r.json()).value || [])[0] || null;
    }
  } catch (e) { console.warn('[social card] lookup failed:', e.message); }
  if (!listing) return next();

  const price = Number(listing.ListPrice) || 0;
  const bits = [
    listing.BedroomsTotal ? listing.BedroomsTotal + ' bd' : null,
    listing.BathroomsTotalInteger ? listing.BathroomsTotalInteger + ' ba' : null,
    listing.LivingArea ? Number(listing.LivingArea).toLocaleString() + ' sqft' : null,
  ].filter(Boolean).join(' \u00b7 ');

  // Social platforms render og:title large and bold and og:description in small
  // gray text, so the brokerage name leads the title — AREC 790-X-3-.16.
  const title = `${BROKERAGE_NAME} \u2014 ${listing.UnparsedAddress || ''}`
              + `${listing.City ? ', ' + listing.City : ''}`
              + `${price ? ' \u00b7 $' + price.toLocaleString() : ''}`;
  const desc = bits || 'View this listing at bamacoast.com';
  const pageUrl = `${req.protocol}://${req.get('host')}/?listing=${encodeURIComponent(listingKey)}`;
  const photos = Array.isArray(listing.Media)
    ? listing.Media.map(m => (typeof m === 'string' ? m : (m && (m.MediaURL || m.MediaUrl)))).filter(Boolean)
    : [];
  const imageUrl = photos[0] || `${req.protocol}://${req.get('host')}/assets/logo.png`;

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

  const b = req.body || {};
  const { to, subject, message } = b;
  /* Gmail previews an .html attachment as raw source, so a report sent that way
     arrives looking like code. Sending the same markup as the email body means
     it renders on arrival; the attachment stays for filing. */
  const htmlBody = typeof b.html === 'string' ? b.html.slice(0, 900000) : '';
  const recipients = String(to || '').split(/[,;]/).map(x => x.trim()).filter(Boolean);
  if (!recipients.length) return res.status(400).json({ error: 'Who should it go to?' });
  if (recipients.length > 10) return res.status(400).json({ error: 'Ten recipients at most.' });

  /* Accepts either a single attachment or a list. Sending four documents used to
     mean four separate emails, which is a nuisance for whoever receives them. */
  const list = Array.isArray(b.attachments) && b.attachments.length
    ? b.attachments
    : (b.dataBase64 ? [{ filename: b.filename, dataBase64: b.dataBase64, mimeType: b.mimeType }] : []);
  // an email with nothing attached is perfectly valid — sending someone a link,
  // for instance — so only the message itself is actually required
  if (!list.length && !String(message || '').trim() && !htmlBody) {
    return res.status(400).json({ error: 'Nothing to send.' });
  }
  if (list.length > 12) return res.status(400).json({ error: 'Twelve attachments at most.' });

  let total = 0;
  const attachments = [];
  for (const a of list) {
    if (!a || !a.dataBase64) continue;
    total += Math.ceil(String(a.dataBase64).length * 3 / 4);
    attachments.push({
      filename: String(a.filename || 'document').replace(/[^A-Za-z0-9._-]/g, '') || 'document',
      content: String(a.dataBase64),
      content_type: a.mimeType || 'application/pdf',
    });
  }
  if (total > 18 * 1024 * 1024) {
    return res.status(413).json({ error: 'Those files are too large to email together.' });
  }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: recipients,
        reply_to: sess.email || undefined,
        subject: String(subject || '').slice(0, 200) || 'Documents from ' + BROKERAGE_NAME,
        text: (String(message || '').slice(0, 4000) || 'Attached.') +
              `\n\n\u2014 ${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\nbamacoast.com`,
        ...(htmlBody ? { html: htmlBody } : {}),
        ...(attachments.length ? { attachments } : {}),
      }),
    });
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      console.error('[marketing email] Resend error:', r.status, t.slice(0, 200));
      return res.status(502).json({ error: 'The mail service refused it.' });
    }
    console.log(`[marketing] ${sess.name} emailed ${attachments.length} file(s) to ${recipients.length} recipient(s)`);
    res.json({ ok: true, sent: recipients.length, files: attachments.length });
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
  // an agent must not be able to grant themselves a license.
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
    console.warn(`[license] blocked profile for ${req.params.id}: mentions ${c.term} without a ${c.name} license`);
    return res.status(422).json({
      error: `This mentions "${c.term}" but there is no ${c.name} license on file for this agent. ` +
             `Remove the reference, or ask the broker to add the ${c.name} license first.`,
      state: c.state, term: c.term,
    });
  }

  /* The finished photo is flattened, so keeping it alone means any change starts
     from scratch. photoSource holds the untouched upload (bounded) and photoEdit
     the crop, filter and text settings, so the editor can reopen exactly where it
     was left. */
  const cleanSource = v => {
    const t = String(v || '');
    if (t.length > 700000) return existing.photoSource || '';
    if (t && !/^data:image\/(jpeg|png|webp);base64,/.test(t)) return '';
    return t;
  };
  let photoEdit = existing.photoEdit || null;
  if (b.photoEdit && typeof b.photoEdit === 'object') {
    const j = JSON.stringify(b.photoEdit);
    photoEdit = j.length < 20000 ? b.photoEdit : null;
  } else if (b.photoEdit === null) {
    photoEdit = null;
  }

  const profile = {
    title: clean(b.title), bio: clean(b.bio), photo: cleanPhoto(b.photo),
    photoSource: ('photoSource' in b) ? cleanSource(b.photoSource) : (existing.photoSource || ''),
    photoEdit,
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

/* ---------- crawler-rendered agent pages ----------
   The site is a single-page app, so a crawler asking for /christinathies used to
   get the generic shell: same title, same description, nothing about the agent.
   Google had nothing to index and a shared link previewed as a bare URL — which
   matters now that printed material drives scans to these pages.

   Served only to crawlers; real visitors still get the app. The wording comes
   from the license record for the same reason the page itself does: a profile
   must never imply practice in a state the agent isn't licensed in.           */
function esc(t){
  return String(t || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function agentSeoHtml(a, origin){
  const url = `${origin}/${a.slug}`;
  const role = a.role === 'broker' ? 'Qualifying Broker' : (a.title || 'REALTOR\u00AE');
  const area = a.serviceArea ? ` serving ${a.serviceArea}` : '';
  const title = `${a.name} \u2014 ${role} | ${BROKERAGE_NAME}`;
  const desc = (a.bio && a.bio.trim())
    ? a.bio.trim().replace(/\s+/g, ' ').slice(0, 300)
    : `${a.name}, ${role} with ${BROKERAGE_NAME}${area}. Call ${a.phone} or search every active listing at bamacoast.com.`;
  const img = a.photo && /^https?:/.test(a.photo) ? a.photo : `${origin}/assets/logo.png`;

  const areaServed = [];
  if ((a.licensedStates || []).includes('AL'))
    areaServed.push('Gulf Shores, AL', 'Orange Beach, AL', 'Fairhope, AL', 'Daphne, AL',
                    'Foley, AL', 'Baldwin County, AL', 'Mobile County, AL');
  if ((a.licensedStates || []).includes('FL'))
    areaServed.push('Perdido Key, FL', 'Pensacola, FL');

  const ld = {
    '@context': 'https://schema.org',
    '@type': 'RealEstateAgent',
    name: a.name,
    jobTitle: role,
    url,
    telephone: a.phone,
    image: img,
    worksFor: {
      '@type': 'RealEstateAgent',
      name: BROKERAGE_NAME,
      url: origin,
      telephone: BROKERAGE_PHONE,
    },
    areaServed: areaServed.map(x => ({ '@type': 'Place', name: x })),
  };
  if (a.email) ld.email = a.email;

  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${esc(url)}">
<meta property="og:type" content="profile">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:image" content="${esc(img)}">
<meta property="og:url" content="${esc(url)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(desc)}">
<script type="application/ld+json">${JSON.stringify(ld)}</script>
</head><body>
<h1>${esc(BROKERAGE_NAME)}</h1>
<h2>${esc(a.name)} \u2014 ${esc(role)}</h2>
${a.serviceArea ? `<p>Serving ${esc(a.serviceArea)}.</p>` : ''}
<p>${esc(desc)}</p>
<p><a href="${esc(url)}">${esc(url)}</a> \u00b7 ${esc(a.phone)}</p>
</body></html>`;
}

async function loadAgentForSeo(slug){
  if (!supabase) return null;
  const { data } = await supabase.from('agents')
    .select('id,name,email,phone,role,active').order('name');
  const match = (data || []).find(a => a.active !== false && slugify(a.name) === slugify(slug));
  if (!match) return null;
  const p = (await getSetting('agentPublic:' + match.id)) || {};
  const licensed = licensedStatesOf(p);
  return {
    name: match.name, role: match.role, slug: slugify(match.name),
    phone: p.publicPhone || match.phone || BROKERAGE_PHONE,
    email: p.publicEmail || '',
    title: p.title || '', bio: p.bio || '', photo: p.photo || '',
    licensedStates: licensed,
    serviceArea: serviceAreaSentence(licensed),
  };
}

app.get('/:slug', async (req, res, next) => {
  const slug = req.params.slug || '';
  if (slug.startsWith('api') || slug.includes('.')) return next();
  if (!CRAWLER_UA_PATTERN.test(req.headers['user-agent'] || '')) return next();
  try {
    const a = await loadAgentForSeo(slug);
    if (!a) return next();
    const origin = `${req.protocol}://${req.get('host')}`;
    console.log(`[seo] served agent page for ${slug}`);
    res.set('Content-Type', 'text/html; charset=utf-8').send(agentSeoHtml(a, origin));
  } catch (e) {
    console.error('[seo] agent page failed:', e.message);
    next();
  }
});

app.get('/robots.txt', (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  res.type('text/plain').send(
`User-agent: *
Allow: /
Disallow: /api/

Sitemap: ${origin}/sitemap.xml
`);
});

/* Agent pages are the ones worth indexing individually — listings come and go
   and belong to the MLS, so they are deliberately left out. */
/* ---------- articles: SEO pages the newsletter also uses ----------
   The same writing does two jobs. A piece written for the monthly nurture email
   is also an indexable page at /insights/<slug>, so a stranger searching "gulf
   shores condo fees" lands on it with a lead form attached, and the newsletter
   sends traffic to your own domain rather than someone else's.

   Before this the whole site had two indexable page types: the homepage and
   agent bios. Every article added here is another way to be found. */
function articleSlug(a) {
  return a.slug || slugify(a.title || '').slice(0, 80);
}

/* Seeded so there is something to send and something to index the moment this
   deploys. Written for this coast specifically — the topics a national
   newsletter cannot cover and a local agent gets asked constantly. */
const ARTICLE_DEFAULTS = [
  { id: 'art_insurance', slug: 'gulf-coast-home-insurance-costs',
    title: 'What home insurance actually costs on the Alabama Gulf Coast',
    teaser: 'Wind, flood and hail are three separate conversations, and the difference between a mile inland and on the beach can be thousands a year.',
    body: `Most people budgeting for a home here budget for the house and forget the insurance. On the Alabama Gulf Coast that is the line item that changes the answer.

There are three separate policies to think about, and they are not one product. Standard homeowners covers fire, theft and liability. Wind and hail is frequently carved out into its own policy or its own deductible along the coast. Flood is federal or private, and it is never included in the other two.

The distance from the water matters more than almost anything else. A house a mile inland and a condo on the beach can differ by thousands a year on wind alone. Elevation matters for flood. Roof age and construction matter for wind, and a current wind mitigation certificate can cut the premium meaningfully.

The number that surprises people most is the hurricane deductible, because it is usually a percentage of the insured value rather than a flat figure. On a $500,000 policy a 5% hurricane deductible is $25,000 before anything pays out. That is a very different conversation from a $1,000 deductible, and it is worth having before you are under contract rather than after.

If you are looking at a specific street or building, the honest way to answer this is to get real quotes on that address rather than an average.`,
    updatedAt: '2026-08-01T00:00:00.000Z' },

  { id: 'art_condofees', slug: 'gulf-shores-condo-fees-explained',
    title: 'Condo fees on the Gulf Coast: what you are actually buying',
    teaser: 'Two buildings on the same stretch of beach can be hundreds apart, and the expensive one is sometimes the better deal.',
    body: `Comparing condo fees by the number alone is the most common mistake buyers make here, and it is usually the wrong way round.

Some buildings bundle wind insurance, water, cable, internet and full exterior maintenance into the fee. Others cover the hallways and not much else, and every owner buys their own wind policy separately. The building with the higher fee can easily be the cheaper one to own once you add back what the lower fee does not include.

Then there are reserves. A building that has been funding its reserves properly for years has a higher monthly fee and no nasty surprises. A building that has kept fees artificially low to look attractive on listings is the one where a special assessment arrives after a storm. Ask for the reserve study and the last two years of minutes before you get attached to a unit.

Rental rules matter as much as money if any part of the plan is renting it out. Some buildings allow nightly rentals, some require a week minimum, some are owner-occupied only. That single rule can change the income by a factor of three.

The short version: ask what the fee covers, what the reserves look like, and what the rental rules are. Those three answers tell you more than the fee itself.`,
    updatedAt: '2026-08-01T00:00:00.000Z' },

  { id: 'art_wherelive', slug: 'fort-morgan-gulf-shores-orange-beach-perdido-key',
    title: 'Fort Morgan, Gulf Shores, Orange Beach or Perdido Key?',
    teaser: 'People treat this as one beach. It is really five or six markets, and the difference matters more than most expect.',
    body: `From Fort Morgan to Perdido Key is about forty miles of coast, and choosing between them is the decision that most affects whether you enjoy the place.

Fort Morgan is the quiet end. Fewer people, fewer restaurants, a longer drive for groceries, and the beach largely to yourself in February. If quiet is the point, this is the answer. If you want to walk to dinner, it is not.

Gulf Shores is the centre of gravity. The most amenities, the most rental demand, the most traffic in July. Good if you want things open year round and you accept the season.

Orange Beach has the bigger buildings and the marinas. If boating matters, this is usually where the answer lands. It also has some of the strongest rental performance on the coast.

Perdido Key sits across the Florida line, which changes the tax picture and the licensing, and it is quieter than Orange Beach without being as remote as Fort Morgan.

Inland — Foley, Elberta, Robertsdale — is where the same money buys substantially more house and land, at the cost of a fifteen to thirty minute drive to the water. A lot of people who arrive certain they want beachfront end up here once they see the difference in what they get.

The right question is not which is best. It is how you will actually use it: every weekend, two weeks a year, or renting it out most of the season.`,
    updatedAt: '2026-08-01T00:00:00.000Z' },
];

async function articlesAll() {
  const saved = await getSetting(ARTICLES_KEY);
  const list = Array.isArray(saved) && saved.length ? saved : ARTICLE_DEFAULTS;
  return list.map(a => Object.assign({}, a, { slug: articleSlug(a) }));
}

/* An article reached through an agent's newsletter belongs to that agent. The
   page carries ?agent=<slug> straight through to the call-to-action, so a lead
   created from it lands on them and not on the brokerage. Attribution here is
   the same rule as everywhere else: it does not expire and it is not silently
   handed back. */
function articleSeoHtml(a, origin, agentSlug) {
  const url = `${origin}/insights/${a.slug}`;
  const esc = t => String(t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const desc = String(a.teaser || '').replace(/\s+/g, ' ').slice(0, 300);
  const paras = String(a.body || '').split(/\n{2,}/)
    .map(p => `<p>${esc(p.trim())}</p>`).join('\n');

  const ld = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: a.title,
    description: desc,
    url,
    datePublished: a.updatedAt || new Date().toISOString(),
    dateModified: a.updatedAt || new Date().toISOString(),
    author: { '@type': 'Organization', name: BROKERAGE_NAME, url: origin },
    publisher: {
      '@type': 'RealEstateAgent', name: BROKERAGE_NAME, url: origin,
      telephone: BROKERAGE_PHONE, address: BROKERAGE_ADDRESS,
    },
    about: ['Gulf Shores', 'Orange Beach', 'Baldwin County', 'Alabama Gulf Coast']
      .map(x => ({ '@type': 'Place', name: x })),
  };

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(a.title)} | ${esc(BROKERAGE_NAME)}</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${url}">
<meta property="og:type" content="article">
<meta property="og:title" content="${esc(a.title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${url}">
<script type="application/ld+json">${JSON.stringify(ld)}</script>
<style>
body{margin:0;background:#FBFAF7;color:#141A3C;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:720px;margin:0 auto;padding:38px 22px 70px}
a{color:#C89B4E}
.eb{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#C89B4E;font-weight:700}
h1{font-family:Georgia,serif;font-size:34px;line-height:1.15;font-weight:400;margin:12px 0 10px}
.te{font-size:17px;color:#3D456B;margin:0 0 26px}
p{font-size:16px;margin:0 0 18px}
.cta{margin-top:38px;padding:24px;background:#fff;border:1px solid rgba(20,26,60,.1);
  border-left:3px solid #C89B4E;border-radius:4px}
.cta h2{font-family:Georgia,serif;font-size:22px;font-weight:400;margin:0 0 8px}
.cta p{font-size:15px;color:#3D456B}
.btn{display:inline-block;background:#C89B4E;color:#241A08;text-decoration:none;
  padding:12px 22px;border-radius:3px;font-weight:700;font-size:13px;
  letter-spacing:.05em;text-transform:uppercase;margin-top:6px}
.ft{margin-top:44px;padding-top:20px;border-top:1px solid rgba(20,26,60,.1);
  font-size:13px;color:#7A8199}
</style></head><body><div class="w">
<div class="eb">Alabama Gulf Coast</div>
<h1>${esc(a.title)}</h1>
<p class="te">${esc(desc)}</p>
${paras}
<div class="cta">
  <h2>Want this answered for a specific address?</h2>
  <p>Averages are only useful up to a point. Tell us the street or the building and
     we will give you the real numbers for it.</p>
  <a class="btn" href="${origin}/?ask=${encodeURIComponent(a.slug)}${agentSlug ? '&agent=' + encodeURIComponent(agentSlug) : ''}">Ask about a property</a>
</div>
<div class="ft">${esc(BROKERAGE_NAME)} &middot; ${esc(BROKERAGE_PHONE)}<br>
${esc(BROKERAGE_ADDRESS)}<br>
<a href="${origin}/">Search every active listing on the Alabama Gulf Coast</a></div>
</div></body></html>`;
}

app.get('/insights', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const list = await articlesAll();
  const esc = t => String(t || '').replace(/</g, '&lt;');
  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gulf Coast buying and selling guides | ${esc(BROKERAGE_NAME)}</title>
<meta name="description" content="Straight answers about buying and selling on the Alabama Gulf Coast — insurance, condo fees, and where to actually live.">
<link rel="canonical" href="${origin}/insights">
<style>body{margin:0;background:#FBFAF7;color:#141A3C;font-family:'Public Sans',system-ui,sans-serif;line-height:1.7}
.w{max-width:720px;margin:0 auto;padding:38px 22px 70px}a{color:#141A3C;text-decoration:none}
h1{font-family:Georgia,serif;font-size:34px;font-weight:400;margin:0 0 26px}
.it{padding:20px 0;border-bottom:1px solid rgba(20,26,60,.1)}
.it h2{font-family:Georgia,serif;font-size:21px;font-weight:400;margin:0 0 6px}
.it p{margin:0;color:#3D456B;font-size:15px}</style></head><body><div class="w">
<h1>Guides to buying and selling here</h1>
${list.map(a => `<div class="it"><a href="${origin}/insights/${a.slug}">
  <h2>${esc(a.title)}</h2><p>${esc(a.teaser)}</p></a></div>`).join('\n')}
</div></body></html>`);
});

app.get('/insights/:slug', async (req, res, next) => {
  try {
    const list = await articlesAll();
    const a = list.find(x => x.slug === req.params.slug);
    if (!a) return next();
    const who = String(req.query.agent || '').slice(0, 60).replace(/[^a-z0-9-]/gi, '');
    res.type('html').send(articleSeoHtml(a, `${req.protocol}://${req.get('host')}`, who));
  } catch (e) { next(); }
});

app.get('/sitemap.xml', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const urls = [{ loc: origin + '/', pri: '1.0' }];
  try {
    if (supabase) {
      const { data } = await supabase.from('agents').select('name,active').order('name');
      (data || []).filter(a => a.active !== false).forEach(a => {
        urls.push({ loc: origin + '/' + slugify(a.name), pri: '0.8' });
      });
    }
  } catch (e) { console.warn('[sitemap] agent list failed:', e.message); }
  // articles: the only pages besides the homepage and agent bios that Google can index
  try {
    urls.push({ loc: origin + '/insights', pri: '0.7' });
    (await articlesAll()).forEach(a => {
      urls.push({ loc: origin + '/insights/' + a.slug, pri: '0.7' });
    });
  } catch (e) { console.warn('[sitemap] articles failed:', e.message); }
  const today = new Date().toISOString().slice(0, 10);
  res.type('application/xml').send(
`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${u.loc}</loc><lastmod>${today}</lastmod><priority>${u.pri}</priority></url>`).join('\n')}
</urlset>
`);
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
