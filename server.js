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
/* \u26a0 A background sweep has no req, so it cannot build an origin the way every route
   does. Set PUBLIC_ORIGIN in the host environment if the domain ever changes; the
   fallback is the live site. An origin that is wrong here breaks the unsubscribe
   link, which is the one link with a statutory penalty behind it. */
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || 'https://bamacoast.com').replace(/\/+$/, '');
const BROKERAGE_PHONE = '251-229-3216';

const app = express();

/* ==================== HTTPS BEHIND THE PROXY ====================
   \u26a0 GoDaddy terminates TLS in front of this process, so the request that arrives
   here is plain HTTP. Without `trust proxy`, `req.protocol` returns "http" and the
   TWENTY-TWO places that build `${req.protocol}://${req.get('host')}` all emit
   http:// URLs. That was live and it was doing real damage:

     - sitemap.xml advertised http:// URLs to Google
     - every article and area page emitted an http:// <link rel="canonical">, which
       Google treats as a different origin from the https:// page it crawled
     - OG tags, agent-page URLs and listing share links, all http://
     - password reset, client reset and agent login links, emailed as http://
     - click-tracking and listing-photo URLs inside alert emails

   `trust proxy` makes Express read X-Forwarded-Proto, which fixes all of them at once
   rather than editing twenty-two call sites and hoping the twenty-third remembers. */
app.set('trust proxy', true);

/* \u26a0 Belt and braces: if the proxy does not send X-Forwarded-Proto at all, trust proxy
   has nothing to read and req.protocol stays "http". Anything that is not a local
   development host is served over https in practice, so force it. Shadows the getter
   on the request object itself, which keeps all twenty-two call sites untouched. */
app.use((req, res, next) => {
  const host = String(req.get('host') || '');
  const local = /^(localhost|127\.0\.0\.1|\[::1\])(:|$)/.test(host);
  if (!local && req.protocol !== 'https') {
    Object.defineProperty(req, 'protocol', { value: 'https', configurable: true });
  }
  next();
});

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

// GET a single key -> { key, value }. A key that was never written comes back as
// value:null with missing:true, NOT a 404 — absent is a normal state here.
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
    /* \u26a0 A key that has never been written is a NORMAL state for a key-value store,
       not a failure. Answering 404 made the browser log a red error on every page
       load for every feature nobody has set up yet \u2014 drip campaigns, tasks, deal
       submissions, plan history \u2014 and five permanent red lines is how you stop
       reading the console at all. That is not free: the counters reading zero and the
       flyer autofill throwing both sat in that noise.
       storeGet() already turns 404 into null, so it keeps working either way. */
    if (!data) return res.json({ key: req.params.key, value: null, missing: true });

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

  /* ⚠ The public search used to stop at city / type / beds / price while listing
     alerts matched on fourteen things. Someone could not search for what we would
     happily email them, which made the alert sign-up look like a different product.
     These mirror searchFilter() so the two agree. */
  const baths = num(q.baths);      if (baths)  parts.push(`BathroomsTotalInteger ge ${baths}`);
  const sqft  = num(q.sqft);       if (sqft)   parts.push(`LivingArea ge ${sqft}`);
  const sqftMax = num(q.sqftMax);  if (sqftMax) parts.push(`LivingArea le ${sqftMax}`);
  const acres = num(q.acres);      if (acres)  parts.push(`LotSizeAcres ge ${acres}`);
  const year  = num(q.yearBuilt);  if (year)   parts.push(`YearBuilt ge ${year}`);
  const stories = num(q.stories);  if (stories) parts.push(`StoriesTotal eq ${stories}`);
  const garage = num(q.garage);    if (garage) parts.push(`GarageSpaces ge ${garage}`);
  const maxHoa = num(q.maxHoa);    if (maxHoa) parts.push(`AssociationFee le ${maxHoa}`);

  if (q.pool === '1')        parts.push(`PoolPrivateYN eq true`);
  if (q.waterfront === '1')  parts.push(`WaterfrontYN eq true`);
  if (q.view === '1')        parts.push(`ViewYN eq true`);
  if (q.newConstruction === '1') parts.push(`(contains(PropertyCondition,'New') or YearBuilt ge ${new Date().getFullYear() - 1})`);
  if (q.noHoa === '1')       parts.push(`(AssociationYN eq false or AssociationFee eq 0)`);

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
    /* \u26a0 One pull, shared with the monthly market letter. Two functions computing
       "the market" from two separate fetches is how the letter says 47 homes and the
       website says 45 on the same morning. */
    const rows = await marketRows();

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
    /* \u26a0 Merge, do not replace \u2014 reassigning the whole object dropped the shared
       rows and made the next letter re-pull 1,200 records for nothing. */
    marketCache.data = payload; marketCache.at = Date.now();
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
    sendMail: async ({ to, subject, text, html, marketing }) => {
      const from = marketing && MARKETING_READY ? RESEND_MARKETING_FROM : RESEND_FROM;
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        // ⚠ html is optional; when present Resend sends multipart and `text` is the
      //   fallback for clients that will not render it.
      body: JSON.stringify(html ? { from, to, subject, text, html } : { from, to, subject, text }),
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
    /* \u26a0 Day 0 added so this can be used for somebody who has JUST asked what their
       home is worth and said they are only curious. Without it the sequence opened at
       day 30 and they heard nothing for a month after asking a direct question - the
       fastest way to look like a machine that ignored them. Answer today, no pitch,
       then leave them alone. */
    { d:0, ch:'email', s:'Your home\u2019s value \u2014 no pitch',
      t:"Hi {first},\n\nThanks for asking about {address}. You said you are mostly curious rather than ready to sell, so I will keep this simple and leave you alone after it.\n\nI will put a proper number together \u2014 not an automated estimate, but one that accounts for what you have actually done to the place. Reply with anything a computer would not know: work you have had done, how the outlook is, anything unusual about the lot.\n\nNo timeline, no pressure. Curious is a perfectly good reason to ask.\n\n{agent}" },
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
  /* ⚠ Between 'asked to see a property' (30) and 'has definite plans to sell'
     (25). Opening a valuation of your own house is not casual reading. */
  cma_open:         { pts: 22, why: 'opened the valuation of their home' },
  /* \u26a0 Below cma_open. Watching a video you were sent is real interest, but opening a
     valuation of your own house is a stronger signal than watching a walkthrough. */
  video_play:       { pts: 14, why: 'watched a video we sent' },
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
  if (!await mustSet(res, 'settings:playbooks', list.slice(0, 40))) return;
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
/* ⚠ IDX ATTRIBUTION — MANDATORY, NOT COSMETIC.
   Any listing shown or sent that is not our own must name the brokerage that
   listed it. This is a condition of the MLS/IDX licence, and displaying other
   firms' inventory without it is the kind of thing that costs feed access.
   Every surface that renders a listing goes through this. */
function listingCredit(r) {
  const office = String((r && (r.ListOfficeName || r.listOfficeName)) || '').trim();
  if (!office) return '';
  if (office.toLowerCase() === String(BROKERAGE_NAME).toLowerCase()) return '';
  return 'Listed by ' + office;
}

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
  if (!await mustSet(res, 'savedSearch:' + sess.agentId + ':' + id, rec)) return;
  if (!await mustSet(res, 'ssTok:' + searchToken(id),
        { key: 'savedSearch:' + sess.agentId + ':' + id })) return;
  console.log(`[search] ${sess.name} set up "${searchLabel(rec.criteria)}" for ${rec.name || rec.email}`);
  res.json({ ok: true, search: rec });
});

/* ==================== PUBLIC ALERT SIGN-UP (server 110) ====================
   The gap this closes: the public "Set up listing alerts" button created a LEAD and
   nothing else. No saved search was ever written, so nobody who asked for alerts on
   the public site ever received one until an agent noticed and built it by hand. The
   alert engine, the criteria fields fixed in v210 and the matching in searchFilter()
   were all sitting there with no public door to them.

   \u26a0 This is the only unauthenticated route that writes a savedSearch record, so it
   validates hard and rate-limits by IP. Everything it writes is owned by a real
   agent, resolved server-side from the slug — the visitor does not get to name an
   owner, they get to name the agent whose link they arrived on. */

const QUIZ_IPS = new Map();
const QUIZ_CAP = 8;                       // per IP per hour
function quizRateOk(ip) {
  const hour = Math.floor(Date.now() / 3600000);
  const key = hour + ':' + ip;
  const n = (QUIZ_IPS.get(key) || 0) + 1;
  QUIZ_IPS.set(key, n);
  if (QUIZ_IPS.size > 2000) {
    for (const k of QUIZ_IPS.keys()) if (!k.startsWith(hour + ':')) QUIZ_IPS.delete(k);
  }
  return n <= QUIZ_CAP;
}

/* Timeline is the single most useful thing a quiz collects, so it decides the lane
   rather than sitting in a notes field. The lane engine then runs its own rules from
   there — this only sets the starting point. */
function laneFromTimeline(t) {
  if (t === 'now' || t === 'ready') return 'fast';
  if (t === 'soon') return 'steady';
  return 'slow';
}


/* ==================== EDITABLE QUIZ (server 113) ====================
   The broker asked to add and edit the questions. Fair housing is the reason this
   needs a gate rather than a plain text box: a public form is exactly where steering
   language does damage, and it does damage under the brokerage's licence.

   \u26a0 The gate is a WARNING, not a veto. The broker knows fair housing and asked to be
   shown flags and allowed to confirm \u2014 so a flagged save is refused ONCE, returns
   what tripped and why, and goes through on a second request carrying acknowledged.
   Every acknowledged flag is logged with who confirmed it and when, because the value
   of the log is that it exists if anyone ever asks.

   \u26a0 Nothing here can change the ANSWER SHAPES the rest of the system depends on.
   `key` is fixed to the known set: rewriting a key to something searchFilter() has
   never heard of would produce an alert quietly matching nothing. Wording is the
   broker's; plumbing is not. */

const QUIZ_KEYS = {
  buy:  ['cities', 'type', 'maxPrice', 'beds', 'musts', 'timeline'],
  sell: ['address', 'ptype', 'timeline', 'situation'],
};

async function quizConfig() {
  const saved = await getSetting('settings:quizConfig');
  return (saved && saved.buy && saved.sell) ? saved : null;   // null = client defaults
}

/* Public. The quiz itself has to read this before anybody has signed in. */
app.get('/api/quiz-config', async (req, res) => {
  res.json({ ok: true, config: await quizConfig() });
});

app.post('/api/quiz-config', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });

  const b = req.body || {};
  const cfg = b.config || {};
  const clean = (v, n) => String(v == null ? '' : v).slice(0, n).trim();

  const out = {};
  for (const path of ['buy', 'sell']) {
    const allowed = QUIZ_KEYS[path];
    const steps = Array.isArray(cfg[path]) ? cfg[path] : [];
    out[path] = steps.slice(0, 10).map(s => {
      const step = {
        key: allowed.includes(s.key) ? s.key : allowed[0],
        kind: ['one', 'multi', 'text'].includes(s.kind) ? s.kind : 'one',
        title: clean(s.title, 120),
        sub: clean(s.sub, 240),
        two: !!s.two,
      };
      if (step.kind === 'text') {
        step.fields = (Array.isArray(s.fields) ? s.fields : []).slice(0, 3)
          .map(f => ({ k: clean(f.k, 24) || 'address', l: clean(f.l, 60), ph: clean(f.ph, 90) }));
      } else {
        step.opts = (Array.isArray(s.opts) ? s.opts : []).slice(0, 14).map(o => ({
          v: (typeof o.v === 'number') ? o.v : clean(o.v, 60),
          l: clean(o.l, 90),
          d: clean(o.d, 120),
        })).filter(o => o.l);
      }
      return step;
    }).filter(s => s.title);
  }
  if (!out.buy.length || !out.sell.length) {
    return res.status(400).json({ error: 'Each path needs at least one question.' });
  }

  /* Every word that will appear on a public form, checked in one pass. */
  const flags = [];
  const look = (where, text) => {
    fhScan(text).forEach(h => flags.push({ where, phrase: h.phrase, why: h.why }));
  };
  ['buy', 'sell'].forEach(path => {
    out[path].forEach((s, i) => {
      const at = `${path} \u00b7 question ${i + 1}`;
      look(at + ' \u00b7 title', s.title);
      look(at + ' \u00b7 note', s.sub);
      (s.opts || []).forEach(o => { look(at + ' \u00b7 answer', o.l); look(at + ' \u00b7 answer note', o.d); });
      (s.fields || []).forEach(f => look(at + ' \u00b7 field', f.l + ' ' + f.ph));
    });
  });

  if (flags.length && b.acknowledged !== true) {
    console.warn(`[quiz-config] refused once for ${sess.name || sess.agentId}: `
      + flags.map(f => `"${f.phrase}" (${f.why})`).join(', '));
    return res.status(409).json({ error: 'fairhousing', flags });
  }

  const record = {
    ...out,
    updatedAt: new Date().toISOString(),
    updatedBy: sess.name || sess.agentId,
    /* \u26a0 Kept on the record, not just in the log. If it is ever asked who approved
       wording that got flagged, the answer is on the thing itself. */
    acknowledgedFlags: flags.length ? flags : undefined,
  };
  await setSetting('settings:quizConfig', record);
  if (flags.length) {
    console.warn(`[quiz-config] SAVED WITH ${flags.length} ACKNOWLEDGED FLAG(S) by `
      + `${record.updatedBy}: ` + flags.map(f => `"${f.phrase}" (${f.why})`).join(', '));
  } else {
    console.log(`[quiz-config] saved clean by ${record.updatedBy}`);
  }
  res.json({ ok: true, flags });
});

/* Back to the built-in questions, for when an edit has gone wrong. */
app.post('/api/quiz-config/reset', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });
  /* \u26a0 Same trap as the CMA delete: setSetting(key, null) upserts a null rather than
     removing the row, and if that is rejected the failure is swallowed and the reset
     silently does nothing. Real delete, error checked. */
  try {
    const { error } = await supabase.from(KV_TABLE).delete().eq('key', 'settings:quizConfig');
    if (error) {
      console.error('[quiz-config] reset FAILED:', error.message);
      return res.status(500).json({ error: 'Could not reset those.' });
    }
  } catch (e) {
    console.error('[quiz-config] reset FAILED:', e.message);
    return res.status(500).json({ error: 'Could not reset those.' });
  }
  console.log(`[quiz-config] reset to defaults by ${sess.name || sess.agentId}`);
  res.json({ ok: true });
});

app.post('/api/alert-signup', async (req, res) => {
  if (!requireSupabase(res)) return;
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (!quizRateOk(ip)) return res.status(429).json({ error: 'Too many sign-ups from here just now.' });

  const b = req.body || {};
  const clean = v => String(v == null ? '' : v).slice(0, 90).trim();
  const num = v => { const n = Number(v); return isFinite(n) && n > 0 ? Math.round(n) : ''; };

  const email = clean(b.email).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'That email address does not look right.' });
  }
  /* \u26a0 Consent is not decoration. The disclosure the visitor ticked is on the form;
     refusing without it here is what makes the record defensible later. */
  if (b.consent !== true) return res.status(400).json({ error: 'We need the consent box ticked.' });

  /* Owner is resolved from the slug on the server. A visitor who arrived on an
     agent's link belongs to that agent; otherwise the qualifying broker. */
  let owner = null;
  try {
    const { data } = await supabase.from('agents').select('id,name,email,role,active').order('name');
    const list = (data || []).filter(a => a.active !== false);
    const slug = clean(b.agentSlug);
    if (slug) owner = list.find(a => slugify(a.name) === slugify(slug)) || null;
    if (!owner) owner = list.find(a => a.role === 'broker') || list[0] || null;
  } catch (e) { return res.status(500).json({ error: 'Could not read the roster.' }); }
  if (!owner) return res.status(503).json({ error: 'No agent is set up to receive this yet.' });

  const c = b.criteria || {};
  const criteria = {
    city: clean(c.city), type: clean(c.type),
    minPrice: num(c.minPrice), maxPrice: num(c.maxPrice),
    beds: num(c.beds), baths: num(c.baths),
    waterfront: !!c.waterfront, pool: !!c.pool,
    view: !!c.view, newConstruction: !!c.newConstruction, noHoa: !!c.noHoa,
    garage: num(c.garage), stories: num(c.stories),
    acres: num(c.acres), sqft: num(c.sqft), maxSqft: num(c.maxSqft),
    yearBuilt: num(c.yearBuilt), maxHoa: num(c.maxHoa),
  };
  if (Array.isArray(c.cities) && c.cities.length) {
    criteria.cities = c.cities.map(clean).filter(Boolean).slice(0, 12);
    if (!criteria.city) criteria.city = criteria.cities[0];
  }
  /* Nothing to match on means an alert that mails them the whole MLS every morning.
     Better to take the lead and let a person set the search. */
  const hasSomething = criteria.city || (criteria.cities || []).length || criteria.maxPrice
    || criteria.beds || criteria.type;
  if (!hasSomething) return res.status(400).json({ error: 'Tell us at least a town or a budget.' });

  const id = 'ss_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  const rec = {
    id, agentId: owner.id, agentName: owner.name || '', agentEmail: owner.email || '',
    leadId: clean(b.leadId), name: clean(b.name), email,
    pace: ['instant', 'daily', 'weekly'].includes(b.pace) ? b.pace : 'daily',
    criteria,
    source: 'quiz',
    consentAt: new Date().toISOString(),
    consentIp: ip.slice(0, 45),
    lastSent: new Date().toISOString(),
    sentKeys: [],
    createdAt: new Date().toISOString(),
  };
  if (!await mustSet(res, 'savedSearch:' + owner.id + ':' + id, rec)) return;
  if (!await mustSet(res, 'ssTok:' + searchToken(id),
        { key: 'savedSearch:' + owner.id + ':' + id })) return;
  console.log(`[quiz] alert "${searchLabel(criteria)}" for ${rec.name || email} \u2192 ${owner.name}`);

  /* Fire and forget, same rule as the open-house sign-in: a mail failure must not
     fail the sign-up, because the record is already saved and it is the record that
     matters. */
  try {
    if (mailer && owner.email) {
      mailer.sendMail({
        to: owner.email,
        subject: `New alert sign-up \u2014 ${rec.name || email}`,
        text: `${rec.name || '(no name)'} just set up listing alerts from the site.\n\n`
            + `Looking for: ${searchLabel(criteria)}\n`
            + `Email: ${email}\n`
            + (clean(b.phone) ? `Phone: ${clean(b.phone)}\n` : '')
            + `\nThey will start receiving matches ${rec.pace}.\n`,
      }).catch(e => console.error(`[quiz] agent notice FAILED for ${owner.email}:`, e.message));
    }
  } catch (e) {}

  res.json({ ok: true, searchId: id, assignedTo: owner.name || '', label: searchLabel(criteria) });
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
    credit: listingCredit(r),
  }));

  /* ⚠ The preview renders the SAME builder the send uses, so what the agent
     approves is literally the email. A preview that drifts from the send is
     worse than no preview. */
  const previewHtml = listingEmailHtml({
    first: name,
    intro: `New since I last wrote, matching ${label}.`,
    rows: rows.slice(0, 6),
    origin,
    agentName: sess.name || '',
    agentSlug: slugify(sess.name || ''),
    unsub: `${origin}/`,
    more: rows.length > 6 ? `Plus ${rows.length - 6} more \u2014 reply and I will send them over.` : '',
  });

  res.json({ ok: true, count: rows.length, label, html: previewHtml,
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
  /* Hand-picked recipients. Still filtered by the same ownership rule below, so
     naming somebody else's lead in the list does not reach them. */
  const picked = Array.isArray(seg.leadIds) && seg.leadIds.length
    ? seg.leadIds.map(String) : null;
  return all.filter(({ lead }) => {
    if (!lead.email || lead.unsubscribed) return false;
    if (!staff && lead.assignedAgentId !== sess.agentId) return false;
    if (picked && !picked.includes(String(lead.id))) return false;
    if (seg.agentId && lead.assignedAgentId !== seg.agentId) return false;
    if (seg.lane && (lead.lane || 'steady') !== seg.lane) return false;
    if (seg.stage && lead.stage !== seg.stage) return false;
    if (seg.type && String(lead.type || '') !== seg.type) return false;
    if (seg.minScore && (lead.score || 0) < Number(seg.minScore)) return false;
    return true;
  });
}

/* ---------- drafting new articles ----------
   ⚠ This drafts. It does not publish, and it must not be made to.

   Google's spam policies target scaled content abuse — pages generated at volume
   primarily to rank. The Master Directive says the same thing in its own words:
   demonstrate real local expertise rather than looking like generic AI real
   estate content. A machine posting four Gulf Shores pieces a week walks
   straight into that, and the penalty lands on the whole domain.

   So: a draft at a time, on a topic the broker picked, published only by a human
   who has read it. Everything below exists to keep it on that side of the line. */

const TOPIC_BANK = [
  'What buyers get wrong about flood zones here',
  'Buying a second home you also want to rent out',
  'What a home inspection turns up most often on the coast',
  'Waterfront versus water view, and what the difference costs',
  'New construction on the Gulf Coast: what to ask the builder',
  'Why beach listings sit in winter and move in spring',
  'Buying land in Baldwin County: what to check first',
  'What retirees ask us most about moving here',
  'Military relocation to the Gulf Coast',
  'Downsizing on the Eastern Shore',
  'What a condo association actually does',
  'Selling a rental property with bookings on the calendar',
  'The difference between Baldwin and Mobile County for buyers',
  'What to look at in a building before you buy in it',
  'Timing a move around hurricane season',
];

app.get('/api/article-topics', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const used = (await articlesAll()).map(a => String(a.title || '').toLowerCase());
  const open = TOPIC_BANK.filter(t =>
    !used.some(u => u.includes(t.toLowerCase().slice(0, 24))));
  res.json({ ok: true, topics: open.length ? open : TOPIC_BANK });
});

app.post('/api/article-draft', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI is not configured. Set ANTHROPIC_API_KEY.' });
  }
  const topic = String((req.body || {}).topic || '').trim().slice(0, 160);
  if (!topic) return res.status(400).json({ error: 'Pick a topic.' });

  const existing = (await articlesAll()).map(a => a.title).slice(0, 20);

  /* ⚠ The rules that keep this useful rather than dangerous. The figures rule is
     the important one: an invented premium or fee is worse than no article. */
  const system = [
    'You write short, plain articles for a small real estate brokerage on the',
    'Alabama Gulf Coast, covering Baldwin County and Mobile County.',
    '',
    'Voice: direct, specific, unhurried. Short sentences. No marketing language,',
    'no "nestled", no "dream home", no exclamation marks, no headings, no lists.',
    'Write the way a knowledgeable person explains something to a friend.',
    'American English.',
    '',
    'HARD RULES:',
    '1. Never invent a specific number. No premiums, fees, prices, percentages,',
    '   interest rates or statistics. Describe how something works and what it',
    '   depends on. If a figure feels necessary, say what it varies with instead.',
    '2. Never give insurance, lending, legal or tax advice. Explain the mechanics',
    '   and say who to ask.',
    '3. Be specific to this coast — Fort Morgan, Gulf Shores, Orange Beach,',
    '   Perdido Key, Foley, Fairhope, Daphne, Spanish Fort, Elberta, Baldwin',
    '   County, Mobile. Anything that would read the same about Florida or Texas',
    '   is not worth writing.',
    '4. 350 to 500 words. Paragraphs separated by a blank line.',
    '5. Do not repeat these existing articles: ' + existing.join('; '),
    '',
    'Return ONLY valid JSON, no fences, no preamble:',
    '{"title":"...","teaser":"one sentence","body":"paragraphs separated by blank lines",',
    '"topic":"regulated if it touches insurance, lending or tax, otherwise general"}',
  ].join('\n');

  try {
    const raw = await callClaude(system, [{ role: 'user', content: 'Write about: ' + topic }], 1800);
    const cleaned = raw.replace(/```json|```/g, '').trim();
    let d;
    try { d = JSON.parse(cleaned); }
    catch (e) { return res.status(502).json({ error: 'The draft came back malformed. Try again.' }); }
    if (!d || !d.title || !d.body) {
      return res.status(502).json({ error: 'The draft came back incomplete. Try again.' });
    }

    /* Belt and braces: if a number slipped through anyway, say so rather than
       quietly handing the broker something to publish. */
    const figures = String(d.body).match(/\$[\d,]+|\b\d+(\.\d+)?\s?%/g) || [];

    const draft = {
      id: 'art_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
      title: String(d.title).slice(0, 160),
      teaser: String(d.teaser || '').slice(0, 500),
      body: String(d.body).slice(0, 20000),
      topic: d.topic === 'regulated' ? 'regulated' : 'general',
      published: false,          // ⚠ never true from here
      draftedAt: new Date().toISOString(),
      draftedBy: 'ai',
    };
    console.log(`[article-draft] "${draft.title}" for ${sess.name || sess.agentId}`);
    res.json({ ok: true, article: draft, figuresFound: figures });
  } catch (e) {
    console.error('[article-draft]', e.message);
    res.status(500).json({ error: 'Could not draft that right now.' });
  }
});

app.get('/api/articles', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const origin = `${req.protocol}://${req.get('host')}`;
  // the preview link is how a draft gets read before anyone decides to publish it
  const staff = isStaff(sess);
  /* ⚠ Agents get published articles only. A draft may contain a figure the broker
     has not checked yet, and the whole point of the approval gate is that nothing
     unreviewed reaches a client. Drafts and preview links are broker-only. */
  const source = staff ? await articlesAll() : await articlesPublic();
  const list = source.map(a => {
    const base = {
      id: a.id, title: a.title, teaser: a.teaser, slug: a.slug,
      published: a.published, topic: a.topic,
      liveUrl: `${origin}/insights/${a.slug}`,
      regulated: articleRegulated(a),
    };
    if (!staff) return base;
    return Object.assign(base, {
      body: a.body,
      previewUrl: `${origin}/insights/${a.slug}?preview=${previewToken(a.slug)}`,
    });
  });
  res.json({ ok: true, articles: list, canWrite: staff });
});

app.post('/api/articles', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  /* \u26a0 isStaff() is broker OR ADMIN, so this route said "Broker only" in its own
     error message while letting admins through. Hiding the buttons is not a control;
     this is. What goes out on a public page under the brokerage name is the broker's
     decision alone. */
  if (sess.role !== 'broker') {
    console.warn(`[content] ${sess.name || sess.agentId} (${sess.role}) blocked from writing articles`);
    return res.status(403).json({ error: 'Only the broker can publish or change articles.' });
  }
  const list = Array.isArray((req.body || {}).articles) ? req.body.articles : null;
  if (!list) return res.status(400).json({ error: 'Send an articles array.' });
  const clean = list.slice(0, 200).map(a => ({
    id: String(a.id || 'art_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
    title: String(a.title || '').slice(0, 160),
    teaser: String(a.teaser || '').slice(0, 500),
    body: String(a.body || '').slice(0, 20000),
    url: String(a.url || '').slice(0, 400),
    image: String(a.image || '').slice(0, 400),
    /* ⚠ These two were being dropped on every save, which silently unpublished
       anything the broker had turned on and lost the disclaimer classification. */
    published: a.published === true,
    topic: a.topic === 'regulated' ? 'regulated' : (a.topic === 'general' ? 'general' : ''),
    /* ⚠ And this one. Dropping the slug sent the page back to a generated
       fallback, breaking every link already published or emailed. */
    slug: articleSlugify(a.slug || a.title || ''),
    updatedAt: new Date().toISOString(),
  })).filter(a => a.title);
  if (!await mustSet(res, ARTICLES_KEY, clean)) return;
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

/* ==================== UNSUBSCRIBE, THE PAGE (server 134) ====================
   ⚠ Every marketing email built its opt-out as `/?unsub=<id>.<token>` — the SPA
   homepage with a query string — and NOTHING in the client has ever read that
   parameter. The app parses `listing`, `agent`, `leaveReview`, `oh` and `ohf`. Not
   `unsub`. So the link loaded the homepage and silently did nothing, on the welcome,
   the market letter and every drip message. Three places built the same wrong URL.

   The working handler existed the whole time at /api/unsub/:pair. Nothing pointed at
   it. Grep for the write, then grep for the READ — a live route nobody links to is the
   same dead feature as a field nobody sets.

   ⚠ This is the one link that has to work. A broken opt-out is what turns a complaint
   into a penalty, and it is also simply what we told the person we would do.

   ⚠ Server-rendered, not the app shell. It must work with JavaScript off, in a preview
   pane, in whatever a mail client wraps links in. Same reasoning as the listing share
   pages: if it matters outside the app, the server renders it.

   ⚠ GET unsubscribes. Some scanners pre-fetch links, so a scanner could opt somebody
   out — but the alternative is a person clicking Unsubscribe, seeing a button, not
   pressing it, and staying on the list. Being wrongly removed is recoverable and
   harmless; failing to remove somebody who asked is neither. */
app.get('/unsub/:pair', async (req, res) => {
  const raw = String(req.params.pair || '');
  const [leadId, token] = raw.split('.');

  const page = (heading, body, tone) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${heading} — ${esc(BROKERAGE_NAME)}</title>
<style>
  body{margin:0;background:#FBFAF7;color:#171F63;
    font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}
  .w{max-width:540px;margin:0 auto;padding:56px 22px}
  .b{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:#8C93AD;
    font-weight:700;margin-bottom:26px}
  h1{font-size:25px;line-height:1.25;margin:0 0 14px;font-weight:600}
  p{margin:0 0 14px;color:#3C4472}
  .ok{color:#2F7A55;font-weight:600}
  .f{margin-top:34px;padding-top:18px;border-top:1px solid #E4E1D9;
    font-size:13px;color:#8C93AD;line-height:1.55}
  a{color:#171F63}
</style></head><body><div class="w">
  <div class="b">${esc(BROKERAGE_NAME)}</div>
  <h1 class="${tone === 'ok' ? 'ok' : ''}">${heading}</h1>
  ${body}
  <div class="f">${esc(BROKERAGE_NAME)}<br>${esc(BROKERAGE_ADDRESS)}<br>
    ${esc(BROKERAGE_PHONE)}</div>
</div></body></html>`;

  /* ⚠ A bad or expired link still gets a human answer and a phone number, never a 404
     or raw JSON. Somebody trying to get off a list and hitting an error page is exactly
     who ends up pressing "report spam" instead. */
  if (!leadId || token !== unsubToken(leadId)) {
    res.status(404).set('Cache-Control', 'no-store');
    return res.send(page('That link did not work',
      `<p>It may have been broken by your email program, or it may be an old one.</p>
       <p>Reply to any email from us, or call ${esc(BROKERAGE_PHONE)}, and we will take
       you off the list by hand. You do not need this link for that.</p>`));
  }

  const lead = await getSetting('lead:' + leadId);
  if (!lead) {
    res.status(404).set('Cache-Control', 'no-store');
    return res.send(page('You are not on our list',
      `<p>We could not find that record, which most likely means you have already been
       removed. Nothing further will come from us.</p>`));
  }

  const already = !!lead.unsubscribed;
  if (!already) {
    lead.unsubscribed = true;
    lead.unsubscribedAt = new Date().toISOString();
    /* ⚠ Stop the sequence too. Unsubscribing from "emails" while a drip carries on is
       the same failure from the recipient's side. */
    if (lead.drip) lead.drip.stopped = true;
    lead.events = Array.isArray(lead.events) ? lead.events : [];
    lead.events.push({ k: 'unsubscribed', at: lead.unsubscribedAt });
    const ok = await setSetting('lead:' + leadId, lead);
    if (!ok) {
      /* ⚠ Never tell somebody they are unsubscribed when the write failed. That is the
         one lie with a statutory penalty attached. */
      console.error(`[unsub] WRITE FAILED for ${lead.email || leadId} — still subscribed`);
      res.status(500).set('Cache-Control', 'no-store');
      return res.send(page('Something went wrong',
        `<p>We could not record that just now, and we will not tell you it worked when
         it did not.</p>
         <p>Please reply to the email, or call ${esc(BROKERAGE_PHONE)}, and we will
         remove you by hand today.</p>`));
    }
    console.log(`[unsub] ${lead.email || leadId} unsubscribed via the page`);
  }

  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.send(page(already ? 'You were already unsubscribed' : 'You are unsubscribed', `
    <p>${esc(lead.email || 'That address')} will not receive any more marketing email
    from us — no market letters, no listing alerts, no introductions.</p>
    <p>If you are working with one of our agents, they can still reply to you directly
    about your own sale or purchase. That is not marketing and it is not affected by
    this.</p>
    <p>Removed by mistake, or changed your mind? Call ${esc(BROKERAGE_PHONE)} and we
    will put you back.</p>`, 'ok'));
});

/* ==================== DATASET PROBE (server 135) ====================
   ⚠ Built because the Bridge dashboard's status column does not answer the only
   question that matters. `gcmls2` has never shown as granted there and has been
   serving this site's listings for months. So "pending" next to Baldwin says nothing
   about whether the token can actually read it — the only way to find out is to ask.

   This asks. It takes a dataset code, makes one small request with the live server
   token, and reports exactly what came back: the HTTP status, the error body if there
   is one, the total record count, and one sample listing. It changes NO configuration
   and writes nothing. Run it against a code before putting that code anywhere near
   the environment variables.

   ⚠ Broker only, and the token never leaves the server — which is the point of doing
   this here rather than pasting an access_token into a browser address bar, where it
   would land in history, in any sync, and in the referrer of whatever loads next. */
app.get('/api/mls-probe', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  /* ⚠ `sess.role === 'broker'` directly. The notes refer to an isOwner() helper; it is
     not in this file. isStaff() would let admins through, and `broker-only` meaning
     "broker or admin" is a bug this project has already shipped once. */
  if (!sess || sess.role !== 'broker') return res.status(403).json({ error: 'Broker only.' });

  const dataset = String(req.query.dataset || '').trim().slice(0, 60);
  if (!dataset) {
    return res.status(400).json({ error: 'Give me a dataset code, e.g. ?dataset=gcmls2' });
  }
  /* ⚠ TWO ACCOUNTS, TWO KEYS. Bridge confirmed (server 136) that Baldwin is a separate
     Bridge account from Gulf Coast — separate login, separate credentials, and they
     cannot be merged, because the Baldwin account is tied to the member record in
     Baldwin's own system. So this is NOT one key opening several datasets, which is
     what an earlier note in this project assumed and got wrong. The 404s on 'baldwin'
     were the Gulf Coast key being asked about a dataset it has no account for.

     When Baldwin approves direct access, set BRIDGE_BALDWIN_TOKEN to the token from
     the Baldwin dashboard. Until then this simply reports that it is not set. */
  const which = String(req.query.key || 'gulf');
  const token = which === 'baldwin'
    ? process.env.BRIDGE_BALDWIN_TOKEN
    : (process.env.BRIDGE_SERVER_TOKEN || process.env.BRIDGE_TOKEN);
  if (!token) {
    return res.status(503).json({
      error: which === 'baldwin'
        ? 'No Baldwin key is set on this server yet. Add BRIDGE_BALDWIN_TOKEN once '
          + 'Baldwin approves direct access and you can log into their Bridge dashboard.'
        : 'No Bridge token is set on this server.',
    });
  }

  const url = `https://api.bridgedataoutput.com/api/v2/OData/${encodeURIComponent(dataset)}/Property`
    + `?access_token=${encodeURIComponent(token)}`
    + `&$top=1&$count=true`;

  const started = Date.now();
  try {
    const r = await fetch(url);
    const ms = Date.now() - started;
    const text = await r.text().catch(() => '');

    if (!r.ok) {
      /* ⚠ The body verbatim, truncated. Bridge distinguishes "this dataset does not
         exist", "your token cannot read it" and "you have no licence" in the message,
         and those three mean very different things to whoever you call next. */
      console.error(`[mls-probe] ${dataset} -> ${r.status} in ${ms}ms: ${text.slice(0, 300)}`);
      return res.json({
        ok: false, dataset, status: r.status, ms,
        detail: text.slice(0, 600),
        reading: r.status === 401 ? 'The token was refused outright.'
              : r.status === 403 ? 'The token is valid but has no access to this dataset.'
              : r.status === 404 ? 'No dataset by that code. Check the short code, not the UUID.'
              : 'See the detail below.',
      });
    }

    let json = {};
    try { json = JSON.parse(text); } catch (e) {}
    const rows = json.value || [];
    const one = rows[0] || null;
    console.log(`[mls-probe] ${dataset} -> 200 in ${ms}ms, ${json['@odata.count']} records`);
    res.json({
      ok: true, dataset, status: 200, ms,
      totalRecords: json['@odata.count'] != null ? json['@odata.count'] : '(not reported)',
      sample: one ? {
        ListingKey: one.ListingKey, StandardStatus: one.StandardStatus,
        City: one.City, UnparsedAddress: one.UnparsedAddress,
        ListPrice: one.ListPrice, ListOfficeName: one.ListOfficeName,
        ModificationTimestamp: one.ModificationTimestamp,
      } : null,
    });
  } catch (e) {
    console.error(`[mls-probe] ${dataset} threw:`, e.message);
    res.status(502).json({ ok: false, dataset, error: e.message });
  }
});

app.post('/api/broadcast', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const seg = b.segment || {};
  if (Array.isArray(b.leadIds) && b.leadIds.length) seg.leadIds = b.leadIds.slice(0, 200);
  const ids = Array.isArray(b.articleIds) ? b.articleIds.slice(0, 6) : [];
  const subject = String(b.subject || '').trim().slice(0, 160);
  const intro = String(b.intro || '').trim().slice(0, 1200);
  const dryRun = b.dryRun !== false;      // ⚠ default is DRY. Sending 400 emails by accident is unrecoverable.

  if (!subject) return res.status(400).json({ error: 'A subject line, at least.' });
  if (!ids.length) return res.status(400).json({ error: 'Pick at least one article.' });

  /* ⚠ Published only, and enforced here rather than trusted from the client —
     otherwise a crafted request could mail out a draft. */
  const arts = (await articlesPublic()).filter(a => ids.includes(a.id));
  if (!arts.length) {
    return res.status(400).json({ error: 'Those articles are not published, or no longer exist.' });
  }

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
      const unsub = `${origin}/unsub/${lead.id}.${unsubToken(lead.id)}`;
      try {
        await mailer.sendMail({
          to: lead.email,
          marketing: true,
          subject,
          text: `Hi ${first},\n\n${intro ? intro + '\n\n' : ''}${items}\n\n`
              + `\u2014\n${sess.name || ''}\n${BROKERAGE_NAME}\n${BROKERAGE_PHONE}\n`
              + `${BROKERAGE_ADDRESS}\n\n`
              + `${arts.some(articleRegulated) ? DISCLAIMER_REGULATED + '\n\n' : ''}`
              + `${DISCLAIMER_EMAIL}\n\nNo longer want these? ${unsub}`,
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
      sent, failed, by: sess.name || sess.agentId, byId: sess.agentId,
      at: new Date().toISOString() });
    await setSetting(BROADCAST_LOG, arr.slice(0, 100));
  } catch (e) {}

  console.log(`[broadcast] "${subject}" \u2014 ${sent} sent, ${failed} failed`);
  res.json({ ok: true, sent, failed, broadcastId: bid });
});

app.get('/api/broadcasts', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const log = await getSetting(BROADCAST_LOG);
  const all = Array.isArray(log) ? log : [];
  const who = sess.name || sess.agentId;
  res.json({ ok: true,
    broadcasts: isStaff(sess) ? all : all.filter(b => b.by === who) });
});

/* ---------- listing cards for email ----------
   ⚠ Tables and inline styles only. Email clients do not support flex, grid, or
   external stylesheets, and Outlook ignores most of what a browser accepts.
   Photos go through /api/listing-photo so the URL is stable, host-allowlisted
   and on our own domain — MLS media URLs expire and get blocked. */
function listingPhotoUrl(r, origin) {
  const media = Array.isArray(r && r.Media) ? r.Media : [];
  const first = media
    .map(m => (typeof m === 'string' ? m : (m && (m.MediaURL || m.MediaUrl))))
    .find(u => typeof u === 'string' && /^https:/.test(u));
  return first ? `${origin}/api/listing-photo?u=${encodeURIComponent(first)}` : '';
}

function listingCardHtml(r, origin, agentSlug) {
  const esc = t => String(t == null ? '' : t)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const price = r.ListPrice ? '$' + Number(r.ListPrice).toLocaleString() : 'Price on request';
  const addr = [r.UnparsedAddress || 'Address on request', r.City].filter(Boolean).join(', ');
  const facts = [
    r.BedroomsTotal ? r.BedroomsTotal + ' bd' : '',
    r.BathroomsTotalInteger ? r.BathroomsTotalInteger + ' ba' : '',
    r.LivingArea ? Number(r.LivingArea).toLocaleString() + ' sqft' : '',
  ].filter(Boolean).join(' &nbsp;&middot;&nbsp; ');
  const credit = listingCredit(r);
  const photo = listingPhotoUrl(r, origin);
  const url = `${origin}/?listing=${encodeURIComponent(r.ListingKey || '')}`
    + (agentSlug ? `&agent=${encodeURIComponent(agentSlug)}` : '');

  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
    style="max-width:520px;margin:0 0 18px;border:1px solid #dcdce4;border-radius:6px;
    overflow:hidden;background:#ffffff">
  ${photo ? `<tr><td style="padding:0">
    <a href="${url}" style="display:block;text-decoration:none">
      <img src="${photo}" width="520" alt="${esc(addr)}"
        style="display:block;width:100%;max-width:520px;height:auto;border:0;outline:none;
        text-decoration:none;object-fit:cover"></a></td></tr>` : ''}
  <tr><td style="padding:16px 18px 18px">
    <div style="font:700 23px/1.15 Georgia,serif;color:#0E1433;margin:0 0 5px">
      <a href="${url}" style="color:#0E1433;text-decoration:none">${price}</a></div>
    <div style="font:400 14px/1.45 Arial,Helvetica,sans-serif;color:#3D456B;margin:0 0 8px">
      ${esc(addr)}</div>
    ${facts ? `<div style="font:400 13px/1.4 Arial,Helvetica,sans-serif;color:#7A8199;
      margin:0 0 12px">${facts}</div>` : ''}
    <a href="${url}" style="display:inline-block;background:#C89B4E;color:#241A08;
      text-decoration:none;padding:10px 20px;border-radius:3px;
      font:700 12px/1 Arial,Helvetica,sans-serif;letter-spacing:.06em;
      text-transform:uppercase">See this one</a>
    ${credit ? `<div style="font:400 11px/1.4 Arial,Helvetica,sans-serif;color:#9aa0b0;
      margin:12px 0 0">${esc(credit)}</div>` : ''}
  </td></tr>
</table>`;
}

/* The whole email: greeting, cards, sign-off, address, unsubscribe. */
function listingEmailHtml({ first, intro, rows, origin, agentName, agentSlug, unsub, more }) {
  const esc = t => String(t == null ? '' : t)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#FBFAF7">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
  style="background:#FBFAF7"><tr><td align="center" style="padding:26px 14px 40px">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" border="0"
  style="max-width:520px;width:100%">
  <tr><td style="font:400 15px/1.6 Arial,Helvetica,sans-serif;color:#141A3C;padding:0 0 6px">
    Hi ${esc(first)},</td></tr>
  ${intro ? `<tr><td style="font:400 15px/1.6 Arial,Helvetica,sans-serif;color:#141A3C;
    padding:0 0 20px">${esc(intro)}</td></tr>` : '<tr><td style="height:14px"></td></tr>'}
  <tr><td>${rows.map(r => listingCardHtml(r, origin, agentSlug)).join('')}</td></tr>
  ${more ? `<tr><td style="font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#3D456B;
    padding:2px 0 16px">${esc(more)}</td></tr>` : ''}
  <tr><td style="font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#141A3C;padding:6px 0 0">
    Want to see any of them? Just reply.</td></tr>
  <tr><td style="padding:22px 0 0;border-top:1px solid #e4e4ec;margin-top:20px;
    font:400 13px/1.6 Arial,Helvetica,sans-serif;color:#7A8199">
    ${esc(agentName || '')}<br>${esc(BROKERAGE_NAME)}<br>${esc(BROKERAGE_PHONE)}<br>
    ${esc(BROKERAGE_ADDRESS)}</td></tr>
  <tr><td style="padding:14px 0 0;font:400 11.5px/1.5 Arial,Helvetica,sans-serif;color:#9aa0b0">
    Listing information is deemed reliable but not guaranteed.
    <a href="${unsub}" style="color:#9aa0b0">Unsubscribe</a></td></tr>
</table></td></tr></table></body></html>`;
}

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
    /* \u26a0 A SELLER never has listingLabel - that is set when somebody enquires about one
       of OUR listings. Their address is what they typed on the quiz, at quiz.address.
       Without this fallback a valuation email said "Thanks for asking about the
       property", which is the one thing it must not be vague about: they gave you an
       address and it read like a form letter that lost it. */
    .replace(/\{address\}/g, lead.listingLabel
      || (lead.quiz && lead.quiz.address)
      || (lead.criteria && lead.criteria.address)
      || 'the property')
    /* \u26a0 {city} is used by the default openers and had NO replacement here, so an
       automated message would have gone out reading "Staying around {city}, or open
       to nearby?" \u2014 to a client, under the brokerage's name. leadTown() is declared
       further down the file; function declarations hoist, so this is safe.
       \u26a0 The fallback is deliberately a phrase that reads as English in the sentence
       rather than an empty string, which would leave "Staying around , or open to". */
    .replace(/\{city\}/g, (function(){
      try { return leadTown(lead) || 'the area'; } catch (e) { return 'the area'; }
    })());
}

/* \u26a0 Any token the copy uses and dripFill does not know about would be delivered
   literally. Belt and braces: strip anything left over rather than mail a curly
   brace to a buyer. Logged, because a token going missing is a content bug worth
   seeing rather than silently swallowing. */
function dripClean(text, where){
  const out = String(text || '');
  const left = out.match(/\{[a-zA-Z_]+\}/g);
  if (left && left.length) {
    console.warn('[drip] unresolved token(s) ' + left.join(',') + ' in ' + (where || 'a step'));
    return out.replace(/\{[a-zA-Z_]+\}/g, '');
  }
  return out;
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
        const unsub = `${origin}/unsub/${lead.id}.${unsubToken(lead.id)}`;
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
          const credit = listingCredit(r);
          return `  ${price} \u2014 ${r.UnparsedAddress || 'Address on request'}`
               + (r.City ? `, ${r.City}` : '') + (bb ? `\n    ${bb}` : '')
               + (credit ? `\n    ${credit}` : '')
               + `\n    ${origin}/?listing=${encodeURIComponent(r.ListingKey)}`;
        }).join('\n\n');
        const firstName = String(rec.name || '').split(' ')[0] || 'there';
        const shown = fresh.slice(0, 8);
        /* ⚠ The card version is the point of the email — a photo, a price and a
           button beats a list of addresses every time. `text` stays as the
           fallback for clients that will not render HTML. */
        const html = listingEmailHtml({
          first: firstName,
          intro: `New since I last wrote, matching ${searchLabel(rec.criteria)}.`,
          rows: shown,
          origin,
          agentName: rec.agentName,
          agentSlug: slugify(rec.agentName || ''),
          unsub: link,
          more: fresh.length > shown.length
            ? `Plus ${fresh.length - shown.length} more \u2014 reply and I will send them over.`
            : '',
        });
        try {
          await mailer.sendMail({
            to: rec.email,
            subject: fresh.length === 1
              ? `One new listing \u2014 ${searchLabel(rec.criteria)}`
              : `${fresh.length} new listings \u2014 ${searchLabel(rec.criteria)}`,
            html,
            text: `Hi ${firstName},\n\n`
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

  /* ⚠ This route created the lead and then told nobody. Somebody could scan the
     code, sign in, and walk out without the agent ever knowing they were there —
     which is the entire point of putting a QR code on the door.
     Both sends are fire-and-forget: a mail failure must never make the visitor's
     sign-in appear to fail, because they are standing in the house waiting. */
  if (mailer) {
    // the agent whose open house it is, falling back to the brokerage address
    let agentTo = '';
    try {
      if (rec.agentId && supabase) {
        const { data } = await supabase.from('agents').select('email')
          .eq('id', rec.agentId).maybeSingle();
        if (data && data.email) agentTo = data.email;
      }
    } catch (e) {}
    if (!agentTo) agentTo = await resolveNotifyAddress();

    if (agentTo) {
      mailer.sendMail({
        to: agentTo,
        subject: `Signed in at your open house: ${name}`,
        text: [
          `${name} just signed in${rec.address ? ' at ' + rec.address : ''}.`,
          '',
          `Email: ${visitor.email || 'not given'}`,
          `Phone: ${visitor.phone || 'not given'}`,
          visitor.hasAgent
            ? 'They said they are already working with an agent, so no lead was created.'
            : (visitor.email ? 'A lead has been created and assigned to you.'
                             : 'No email given, so no lead was created.'),
          '',
          BROKERAGE_NAME,
        ].join('\n'),
      }).then(() => console.log(`[openhouse] notified ${agentTo}`))
        .catch(e => console.error('[openhouse] agent notify failed:', e.message));
    } else {
      console.error('[openhouse] nobody to notify — set NOTIFY_EMAIL or give the agent an email.');
    }

    /* And the visitor, while the house is still fresh in their mind. Four
       checkboxes, which is why people actually answer them. */
    if (visitor.email && !visitor.hasAgent) {
      const origin = `${req.protocol}://${req.get('host')}`;
      const first = String(name).trim().split(/\s+/)[0] || 'there';
      const link = `${origin}/?ohf=${token}.${visitor.id}`;
      mailer.sendMail({
        to: visitor.email,
        subject: `Thanks for coming by${rec.address ? ' \u2014 ' + rec.address : ''}`,
        text: [
          `Hi ${first},`,
          '',
          `Thanks for stopping by${rec.address ? ' ' + rec.address : ' today'}.`,
          '',
          'If you have thirty seconds, four quick questions would help me a lot \u2014 and',
          'it means I only send you places worth your time:',
          link,
          '',
          'Either way, reply to this and I will answer anything about the house or the area.',
          '',
          rec.agentName || '',
          BROKERAGE_NAME,
          BROKERAGE_PHONE,
        ].filter(Boolean).join('\n'),
      }).then(() => console.log(`[openhouse] follow-up sent to ${visitor.email}`))
        .catch(e => console.error('[openhouse] visitor follow-up failed:', e.message));
    }
  } else {
    console.warn('[openhouse] SKIPPED both emails \u2014 mailer not configured.');
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

/* ---------- campaign attribution on the server ----------
   The client stamps leads it creates. This covers the ones that arrive through
   the API — the public lead form and anything added later — so a campaign can
   never be lost just because a new form forgot to call stampLead(). */
function cleanCampaign(c) {
  if (!c || typeof c !== 'object') return null;
  const keep = ['utm_source','utm_medium','utm_campaign','utm_term','utm_content',
                'gclid','fbclid','msclkid','ttclid','li_fat_id',
                'referrer','landedOn','at'];
  const one = o => {
    if (!o || typeof o !== 'object') return null;
    const out = {};
    keep.forEach(k => { if (o[k]) out[k] = String(o[k]).slice(0, 300); });
    return Object.keys(out).length ? out : null;
  };
  const first = one(c.first) || one(c);
  const last = one(c.last);
  if (!first && !last) return null;
  return last ? { first, last } : { first };
}

/* A campaign in words, for the lead card: "Facebook · gulf-shores-condos". */
function campaignLabel(c) {
  const f = c && (c.first || c);
  if (!f) return '';
  const bits = [];
  if (f.utm_source) bits.push(f.utm_source);
  if (f.utm_campaign) bits.push(f.utm_campaign);
  if (!bits.length && f.gclid) bits.push('Google Ads');
  if (!bits.length && f.fbclid) bits.push('Facebook');
  if (!bits.length && f.referrer) {
    try { bits.push(new URL(f.referrer).hostname.replace(/^www\./, '')); } catch (e) {}
  }
  return bits.join(' \u00b7 ');
}

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
  /* \u26a0 The generic reply above is correct and stays \u2014 it stops this route being used to
     discover which addresses have accounts. But it was paired with NO logging and a
     swallowed send error, so when a reset produced no email there was no way to tell
     whether the address matched, whether mail was configured, or whether the send
     failed. Silent to the CALLER is right; silent to the LOG is not. */
  try {
    /* \u26a0 ilike, not eq. Agent emails are lower-cased on creation, but any record made
       before that or edited by hand in Supabase keeps its capitals \u2014 and an exact match
       then finds nothing and reports success. */
    const { data } = await supabase.from('agents')
      .select('id,name,email').ilike('email', normalizedEmail).maybeSingle();
    if (!data) {
      console.warn(`[reset] no agent matches ${normalizedEmail} \u2014 nothing sent`);
      return res.json(genericReply);
    }
    const token = crypto.randomBytes(24).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
    const { error: upErr } = await supabase.from('agents')
      .update({ reset_token: token, reset_expires: expires }).eq('id', data.id);
    if (upErr) {
      console.error(`[reset] could not store the token for ${data.email}:`, upErr.message);
      return res.json(genericReply);
    }
    if (!mailer) {
      console.error('[reset] SKIPPED \u2014 mailer not configured. Set RESEND_API_KEY.');
      return res.json(genericReply);
    }
    const resetUrl = `${req.protocol}://${req.get('host')}/?reset=${token}`;
    try {
      await mailer.sendMail({
        to: data.email,
        subject: `Reset your ${BROKERAGE_NAME} CRM password`,
        text: `Hi ${data.name},\n\nSomeone requested a password reset for your ${BROKERAGE_NAME} CRM account. If this was you, set a new password here (link expires in 1 hour):\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email.`,
      });
      console.log(`[reset] link sent to ${data.email}`);
    } catch (e) {
      console.error(`[reset] send FAILED for ${data.email}:`, e.message);
    }
  } catch (e) {
    console.error('[reset] failed:', e.message);
  }
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
/* ==================== THE KEY-VALUE HELPERS ====================
   \u26a0 These two are the single most load-bearing pair of functions in the file \u2014 55
   call sites between them \u2014 and until server 127 they could not report a failure.

   supabase-js does NOT throw on a database error. It resolves with `{ data, error }`.
   So the `catch` blocks these used to have never fired for the thing they were there
   to catch, and `setSetting` returned TRUE on a failed write. It did not hide
   failures; it reported them as successes.

   That is behind at least three bugs found so far: a removed CMA that stayed on
   screen, a quiz reset that silently did nothing, and a password-reset token that was
   never stored. Only 3 of the 55 callers check the return value, so the log is the
   only place a failure can surface \u2014 which is why every failure now logs. */
async function getSetting(key) {
  if (!supabase) return null;
  try {
    const { data, error } = await supabase.from(KV_TABLE)
      .select('value').eq('key', key).maybeSingle();
    if (error) {
      console.error(`[kv] READ FAILED for "${key}":`, error.message);
      return null;
    }
    return data ? data.value : null;
  } catch (e) {
    console.error(`[kv] READ THREW for "${key}":`, e.message);
    return null;
  }
}

async function setSetting(key, value) {
  if (!supabase) {
    console.error(`[kv] WRITE SKIPPED for "${key}" \u2014 no database configured`);
    return false;
  }
  try {
    const { error } = await supabase.from(KV_TABLE)
      .upsert({ key, value }, { onConflict: 'key' });
    if (error) {
      /* \u26a0 The loud one. A write that fails silently is how a broker presses Save,
         sees "Saved", and finds the change gone tomorrow. */
      console.error(`[kv] WRITE FAILED for "${key}":`, error.message);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`[kv] WRITE THREW for "${key}":`, e.message);
    return false;
  }
}

/* \u26a0 A real delete, because setSetting(key, null) is NOT one \u2014 it upserts a null
   value and leaves the row. Use this. */
/* Write, and answer 500 if it did not stick. Returns false once it has already sent
   the response, so a route reads:  if (!await mustSet(res, key, val)) return;
   \u26a0 27 routes still report success without checking. They all LOG a failure now, which
   is the safety net, but anywhere a person is told "Saved" should use this. */
async function mustSet(res, key, value) {
  const ok = await setSetting(key, value);
  if (!ok) res.status(500).json({ error: 'That did not save. Try again.' });
  return ok;
}

async function delSetting(key) {
  if (!supabase) return false;
  try {
    const { error } = await supabase.from(KV_TABLE).delete().eq('key', key);
    if (error) {
      console.error(`[kv] DELETE FAILED for "${key}":`, error.message);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`[kv] DELETE THREW for "${key}":`, e.message);
    return false;
  }
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


/* ==================== SPEED TO LEAD (server 112) ====================
   The agent copy of a new-lead alert was a plain list of fields ending "Call them
   before someone else does." It did not say the one thing that decides whether to
   stop what you are doing: when they want to move.

   The quiz asks that directly now. "As soon as I find the right one" and "just
   watching the market" are different phone calls and one of them is this afternoon.

   \u26a0 This changes what the notification SAYS. It does not add any new automated
   contact with the lead \u2014 everything here goes to the agent's own inbox and their
   own phone, which is why there is no TCPA question to answer. */

const URGENCY = {
  now:     { rank: 3, label: 'READY NOW',        line: 'Wants to move as soon as they find the right one.' },
  soon:    { rank: 2, label: 'NEXT FEW MONTHS',  line: 'Looking to move in the next few months.' },
  later:   { rank: 1, label: 'LATER THIS YEAR',  line: 'Thinking about later this year.' },
  looking: { rank: 0, label: 'JUST WATCHING',    line: 'Watching the market, no timeline yet.' },
};

/* Turn the quiz answers back into something a person reads in three seconds while
   holding a phone. Falls back quietly for leads that did not come through the quiz. */
function leadBrief(b) {
  const q = b.quiz || {};
  const out = [];
  if (q.path === 'sell') {
    if (q.address)   out.push('Property: ' + q.address);
    if (q.ptype)     out.push('Type: ' + q.ptype);
    if (Array.isArray(q.situation) && q.situation.length) out.push('Notes: ' + q.situation.join(', '));
  } else {
    if (Array.isArray(q.cities) && q.cities.length) out.push('Wants: ' + q.cities.join(', '));
    if (q.type)      out.push('Type: ' + q.type);
    if (q.maxPrice)  out.push('Up to $' + Number(q.maxPrice).toLocaleString());
    if (q.beds)      out.push(q.beds + '+ bedrooms');
    if (Array.isArray(q.musts) && q.musts.length) out.push('Must have: ' + q.musts.join(', '));
  }
  return out;
}

function speedToLeadHtml(b, origin) {
  const esc = t => String(t == null ? '' : t)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const u = URGENCY[(b.quiz || {}).timeline] || null;
  const brief = leadBrief(b);
  const phone = String(b.phone || '').replace(/[^0-9+]/g, '');
  const tone = u && u.rank >= 3 ? '#8A2C22' : u && u.rank === 2 ? '#C9971F' : '#3D456B';

  /* \u26a0 The claim link is the whole point of this email on a phone: one tap, no
     sign-in, no CRM. The token in the URL is the authorisation. */
  const claimUrl = b.id ? `${origin}/claim/${encodeURIComponent(b.id)}/${claimToken(b.id)}` : '';

  const btn = (href, label, bg, fg) =>
    `<a href="${href}" style="display:inline-block;background:${bg};color:${fg};
      text-decoration:none;padding:14px 22px;border-radius:4px;font:700 15px/1 Arial,Helvetica,sans-serif;
      margin:0 8px 8px 0">${label}</a>`;

  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#FBFAF7">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
  style="background:#FBFAF7"><tr><td align="center" style="padding:22px 14px 34px">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0"
  style="max-width:480px;width:100%;background:#ffffff;border:1px solid #dcdce4;border-radius:6px">
  ${u ? `<tr><td style="background:${tone};padding:11px 18px;
    font:700 12px/1 Arial,Helvetica,sans-serif;letter-spacing:.14em;color:#ffffff">
    ${esc(u.label)}</td></tr>` : ''}
  <tr><td style="padding:20px 18px 6px">
    <div style="font:700 24px/1.2 Georgia,serif;color:#0E1433">${esc(b.name || 'Someone')}</div>
    ${u ? `<div style="font:400 14px/1.5 Arial,Helvetica,sans-serif;color:#3D456B;margin-top:5px">
      ${esc(u.line)}</div>` : ''}
  </td></tr>
  ${brief.length ? `<tr><td style="padding:12px 18px 4px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
      style="background:#FBFAF7;border-radius:4px">
      <tr><td style="padding:13px 15px;font:400 14px/1.75 Arial,Helvetica,sans-serif;color:#141A3C">
        ${brief.map(esc).join('<br>')}</td></tr></table></td></tr>` : ''}
  ${b.message ? `<tr><td style="padding:12px 18px 0;
    font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#3D456B">
    &ldquo;${esc(String(b.message).slice(0, 400))}&rdquo;</td></tr>` : ''}
  ${claimUrl ? `<tr><td style="padding:16px 18px 0">
    ${btn(claimUrl, 'Claim this lead', '#171F63', '#ffffff')}
    <div style="font:400 13px/1.6 Arial,Helvetica,sans-serif;color:#7A8199;margin-top:2px">
      Claim within ${CLAIM_MINUTES} minutes or it goes back to the broker.</div>
  </td></tr>` : ''}
  <tr><td style="padding:14px 18px 4px">
    ${phone ? btn('tel:' + phone, 'Call ' + esc(b.phone), '#1F6B49', '#ffffff') : ''}
    ${b.email ? btn('mailto:' + esc(b.email), 'Email them', '#C89B4E', '#241A08') : ''}
  </td></tr>
  <tr><td style="padding:4px 18px 18px;font:400 13px/1.7 Arial,Helvetica,sans-serif;color:#7A8199">
    ${b.email ? esc(b.email) + '<br>' : ''}${b.source ? 'Came in through: ' + esc(b.source) : ''}
    <br><a href="${origin}/#crm" style="color:#C89B4E">Open it in the CRM</a>
  </td></tr>
</table>
<div style="font:400 12px/1.6 Arial,Helvetica,sans-serif;color:#9aa0b0;margin-top:14px;
  max-width:480px">${esc(BROKERAGE_NAME)} &middot; ${esc(BROKERAGE_PHONE)}</div>
</td></tr></table></body></html>`;
}

/* The carrier gateway drops anything long or formatted, so this stays short, plain,
   and leads with the timeline \u2014 the part that decides whether to pull over. */
function speedToLeadSms(b) {
  const u = URGENCY[(b.quiz || {}).timeline];
  const q = b.quiz || {};
  const where = Array.isArray(q.cities) && q.cities.length ? q.cities[0]
              : (q.address ? String(q.address).split(',')[0] : '');
  return [
    u ? u.label : 'NEW LEAD',
    b.name || '',
    b.phone || b.email || '',
    where,
  ].filter(Boolean).join(' - ').slice(0, 140);
}


/* ==================== CLAIMING A LEAD (server 130) ====================
   A lead arrives, the assigned agent gets an email with a Claim button. Tap it and it
   is theirs. Ignore it and after the window it comes back to the broker to decide.

   \u26a0 The timer lives IN THIS PROCESS, not in a browser. The clocks on the CRM screen
   \u2014 the timezone strip, the waiting badges \u2014 all tick in JavaScript on whoever has
   the page open, and stop when the tab closes. They are displays, not schedulers.
   This is setInterval on the server, which runs whether or not anybody is looking.

   \u26a0 The DEADLINE IS STORED ON THE LEAD, never held in memory. A deploy, a crash or a
   platform recycle kills an in-process timer; it must not kill the rule. On restart
   the sweep reads deadlines off the records and carries on, having missed nothing but
   the minute it was down.

   \u26a0 Claiming is not contact. It means "I am on it", not "I have spoken to them", so
   firstTouchAt is untouched and the waiting clock keeps running. Otherwise one tap
   makes somebody vanish off the call list without anyone having rung them. */

const CLAIM_MINUTES = 15;
/* ⚠ The SECOND deadline, added server 137 at the broker's instruction. Claiming is
   not contact — deliberately — which left a free move: claim the lead, never ring
   anybody, and nothing ever happened again. There was a deadline on claiming and
   none on contacting. This is that deadline.

   Set when a lead is claimed, cleared the moment firstTouchAt appears. If it passes
   with the lead still untouched, the lead goes back to the broker exactly the way an
   unclaimed one does. */
const CONTACT_MINUTES = 60;
const CLAIM_START_HOUR = 8;    // Central
const CLAIM_END_HOUR   = 20;

function centralHour(d) {
  /* \u26a0 Not the server's clock. This box could be anywhere; the rule is about whether
     it is a reasonable hour on the Gulf Coast. */
  return Number(new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Chicago', hour: 'numeric', hour12: false,
  }).format(d));
}

/* When the window should end for a lead arriving now.
   \u26a0 Outside working hours the clock does not run \u2014 it starts at 8am. A lead at 2am
   is claimable from 8am, not lost at 2:15am while everyone is asleep. */
function claimDeadline(from) {
  return afterBusinessMinutes(from, CLAIM_MINUTES);
}

/* ⚠ Both deadlines go through here, so the out-of-hours rule can never drift apart
   between them. A lead claimed at 7pm must not be "overdue for a call" at 8pm when
   the office is shut — the hour is served from 8am the next morning instead. */
function afterBusinessMinutes(from, minutes) {
  const d = new Date(from);
  const h = centralHour(d);
  if (h >= CLAIM_START_HOUR && h < CLAIM_END_HOUR) {
    return new Date(d.getTime() + minutes * 60000).toISOString();
  }
  /* Next 8am Central. Built by stepping forward an hour at a time rather than doing
     offset arithmetic, so daylight saving cannot put it an hour out. */
  const next = new Date(d.getTime());
  let guard = 0;
  do { next.setTime(next.getTime() + 3600000); guard++; }
  while (centralHour(next) !== CLAIM_START_HOUR && guard < 48);
  next.setMinutes(0, 0, 0);
  return new Date(next.getTime() + minutes * 60000).toISOString();
}

function contactDeadline(from) {
  return afterBusinessMinutes(from, CONTACT_MINUTES);
}

function claimToken(leadId) {
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('claim:' + leadId).digest('hex').slice(0, 20);
}

/* The page an agent lands on from the email. Deliberately a GET with no session:
   they are on a phone, and making them sign in first defeats the point. The token
   is the authorisation. */
app.get('/claim/:id/:tok', async (req, res) => {
  const id = String(req.params.id || '').slice(0, 80);
  const esc = t => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;');
  const page = (head, body, tone) => res.type('html').send(
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(head)}</title>
<style>body{margin:0;background:#FBFAF7;color:#141A3C;font-family:system-ui,-apple-system,sans-serif;
line-height:1.7}.w{max-width:420px;margin:0 auto;padding:64px 24px}
h1{font-family:Georgia,serif;font-size:27px;font-weight:400;margin:0 0 10px;color:${tone}}
p{font-size:16px;color:#3D456B;margin:0 0 20px}
a{display:inline-block;background:#171F63;color:#fff;text-decoration:none;padding:13px 24px;
border-radius:4px;font-weight:700;font-size:15px}</style></head><body><div class="w">
<h1>${esc(head)}</h1>${body}</div></body></html>`);

  if (claimToken(id) !== String(req.params.tok || '')) {
    return page('That link is not valid', '<p>Check the most recent email.</p>', '#8A2C22');
  }
  const lead = await getSetting('lead:' + id);
  if (!lead) return page('That lead is no longer there', '<p>It may have been removed.</p>', '#8A2C22');

  const origin = `${req.protocol}://${req.get('host')}`;
  if (lead.claimedBy) {
    /* \u26a0 Says WHO has it. "Already claimed" with no name just leaves the person
       wondering, and they will ask anyway. */
    return page('Already claimed',
      `<p>${esc(lead.claimedByName || 'Somebody')} took this one`
      + `${lead.claimedAt ? ' at ' + new Date(lead.claimedAt).toLocaleTimeString('en-US',
          { timeZone:'America/Chicago', hour:'numeric', minute:'2-digit' }) + ' Central' : ''}.</p>`
      + `<a href="${origin}/#leads">Open the CRM</a>`, '#7A8199');
  }

  lead.claimedBy = lead.assignedAgentId || '';
  lead.claimedByName = lead.assignedAgentName || '';
  lead.claimedAt = new Date().toISOString();
  lead.claimDue = '';
  /* ⚠ The contact clock starts HERE, on the claim, not on the lead's arrival. Taking
     it is the promise; this is the deadline on keeping it. Cleared by the sweep the
     moment firstTouchAt appears. */
  lead.contactDue = lead.firstTouchAt ? '' : contactDeadline(lead.claimedAt);
  await setSetting('lead:' + id, lead);
  console.log(`[claim] ${lead.name || id} claimed by ${lead.claimedByName || lead.claimedBy}`);
  return page('Got it \u2014 this one is yours',
    `<p>${esc(lead.name || 'This lead')} is assigned to you and will not go back to the broker.</p>`
    /* ⚠ Said plainly, at the only moment they are certain to read it. Nothing in this
       system contacts a new lead for them, and an agent who assumes otherwise costs
       the brokerage the lead. */
    + `<p><strong>You make the first contact.</strong> Nothing is sent to this person`
    + ` automatically \u2014 call or message them yourself within the hour, or this goes`
    + ` back to the broker.</p>`
    + `<p>Once you have spoken to them, log it in the CRM and the follow-up sequence`
    + ` takes over from there.</p>`
    + `<a href="${origin}/#leads">Open the CRM</a>`, '#1F6B49');
});

/* The sweep. Runs on a timer inside this process and reads deadlines off the records,
   so a restart costs at most the minute it was down. */
async function claimSweep() {
  if (!supabase) return;
  try {
    const { data, error } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    if (error) { console.error('[claim sweep] read failed:', error.message); return; }
    const now = Date.now();
    let broker = null;
    for (const row of (data || [])) {
      const l = row.value;
      if (!l) continue;

      /* ---- deadline 2: claimed, and still nobody has spoken to them ----
         ⚠ Checked BEFORE the claim branch, because these are mutually exclusive
         states: claimDue only exists while unclaimed, contactDue only while claimed.
         ⚠ firstTouchAt is written by the CRM, not here, so the sweep is where a met
         deadline gets cleared. Clearing it is not optional — leave it set and the
         lead is dragged back from an agent who did ring them. */
      if (l.contactDue && l.claimedBy) {
        if (l.firstTouchAt) {
          l.contactDue = '';
          await setSetting(row.key, l);
          continue;
        }
        if (new Date(l.contactDue).getTime() > now) continue;

        if (!broker) {
          const { data: ags } = await supabase.from('agents')
            .select('id,name,email,role,active').eq('role', 'broker');
          broker = (ags || []).find(a => a.active !== false) || null;
        }
        if (!broker) { console.warn('[contact sweep] no broker on file'); return; }

        const heldById = l.claimedBy || l.assignedAgentId || '';
        const heldByName = l.claimedByName || l.assignedAgentName || '';
        l.contactDue = '';
        if (heldById === broker.id) { await setSetting(row.key, l); continue; }

        l.assignedAgentId = broker.id;
        l.assignedAgentName = broker.name || '';
        /* ⚠ The claim is released too. Left set, the lead would sit with the broker
           still marked as claimed by the agent who never rang, and could never be
           claimed again by anybody. */
        l.claimedBy = '';
        l.claimedByName = '';
        l.claimedAt = '';
        l.uncontactedFrom = heldByName;
        l.events = Array.isArray(l.events) ? l.events : [];
        l.events.push({ k: 'uncontacted', at: new Date().toISOString(), note: heldByName });
        await setSetting(row.key, l);
        console.warn(`[contact] ${l.name || row.key} claimed by ${heldByName || heldById} `
          + `but never contacted \u2014 back to ${broker.name}`);

        /* ⚠ Told, and told why. This one is sharper than the unclaimed note because
           they did take it on: the difference between missing an email and breaking
           a promise. Still no blame in the wording — the point is the behaviour
           changing, not the agent feeling got at. */
        try {
          if (mailer && heldById) {
            const { data: who } = await supabase.from('agents').select('email,name').eq('id', heldById).maybeSingle();
            if (who && who.email) {
              await mailer.sendMail({
                to: who.email,
                subject: `Back to the broker: ${l.name || 'a lead'}`,
                text: `You claimed ${l.name || 'a lead'}, but there is still nothing logged to show `
                    + `they have been contacted, so after ${CONTACT_MINUTES} minutes it has gone back `
                    + `to ${broker.name}.\n\n`
                    + `First contact is always the agent's own \u2014 nothing in the system reaches out `
                    + `to a new lead for you. Once you have spoken to somebody, log it on their card `
                    + `and the follow-up runs by itself from there.\n\n`
                    + `Nothing is lost \u2014 ask and it can come straight back to you.\n`,
              });
            }
          }
        } catch (e) { console.error('[contact] could not notify:', e.message); }
        continue;
      }

      /* ---- deadline 1: never claimed at all ---- */
      if (!l.claimDue || l.claimedBy) continue;
      if (new Date(l.claimDue).getTime() > now) continue;

      if (!broker) {
        const { data: ags } = await supabase.from('agents')
          .select('id,name,email,role,active').eq('role', 'broker');
        broker = (ags || []).find(a => a.active !== false) || null;
      }
      if (!broker) { console.warn('[claim sweep] no broker on file \u2014 nothing to reassign to'); return; }

      const wasId = l.assignedAgentId || '';
      const wasName = l.assignedAgentName || '';
      if (wasId === broker.id) { l.claimDue = ''; await setSetting(row.key, l); continue; }

      l.assignedAgentId = broker.id;
      l.assignedAgentName = broker.name || '';
      l.claimDue = '';
      l.unclaimedFrom = wasName;
      l.events = Array.isArray(l.events) ? l.events : [];
      l.events.push({ k: 'unclaimed', at: new Date().toISOString(), note: wasName });
      await setSetting(row.key, l);
      console.warn(`[claim] ${l.name || row.key} went unclaimed by ${wasName || wasId} \u2014 back to ${broker.name}`);

      /* \u26a0 The agent is told. Silently taking a lead back is how resentment builds,
         and being told is what changes the behaviour. */
      try {
        if (mailer && wasId) {
          const { data: who } = await supabase.from('agents').select('email,name').eq('id', wasId).maybeSingle();
          if (who && who.email) {
            await mailer.sendMail({
              to: who.email,
              subject: `Unclaimed: ${l.name || 'a new lead'}`,
              text: `${l.name || 'A lead'} came in and was not claimed within ${CLAIM_MINUTES} minutes, `
                  + `so it has gone back to ${broker.name} to reassign.\n\n`
                  + `Nothing is lost \u2014 ask and it can come straight back to you.\n`,
            });
          }
        }
      } catch (e) { console.error('[claim] could not notify:', e.message); }
    }
  } catch (e) { console.error('[claim sweep]', e.message); }
}

/* \u26a0 Every minute, in-process. Node's own scheduler, not a browser and not cron. */
setInterval(() => { claimSweep().catch(() => {}); }, 60 * 1000);

/* ---------- picking the sequence a lead belongs on ----------
   Matches the campaign's `trigger` to how the person actually came in, falling back to
   any "Every new lead" catch-all. A sequence written for open-house sign-ins must not
   go to somebody who asked what their house is worth - that is worse than sending
   nothing, because it proves nobody read it. */
/* ---------- the built-in openers, as live sequences ----------
   \u26a0 The broker's instruction: it has to work without anybody building anything
   first. PLAYBOOK_DEFAULTS already holds real, written copy for every way a person
   comes in - it was only ever a gallery to copy from, so a brokerage that never
   opened that screen got no follow-up at all. These are live now.

   \u26a0 Anything the broker builds himself WINS. This is the floor, not the ceiling:
   the moment a real campaign matches, the default steps out of the way, so editing
   an opener still does exactly what it looks like it does.

   Shape differs and has to be converted: playbook steps are {d, ch, t, s}; the drip
   engine wants {id, day, type, subject, body}. Same conversion the CRM does when you
   press "Use this one", so a default and an edited copy behave identically. */
function playbookToCampaign(pb) {
  if (!pb || !Array.isArray(pb.steps)) return null;
  return {
    id: 'pbdef:' + pb.id,
    name: pb.name || 'Follow-up',
    /* \u26a0 'manual', NOT 'new', when a playbook has no source to match on. Four of the
       built-ins (monthly nurture, snowbird, past client, seller-not-ready) match on
       lane or tag instead and run for a YEAR. Defaulting them to "every new lead"
       made a brand-new buyer eligible for a 365-day monthly drip and nothing but
       list order stopped it happening. Manual means available, never auto-assigned. */
    trigger: (pb.match && pb.match.source) || 'manual',
    paused: false,
    isDefault: true,
    steps: pbSteps(pb),
  };
}

/* \u26a0 Subjects for the instant opener below. The playbook's day-0 step is written as a
   TEXT, so it has no subject line - and an email with no subject is a spam filter's
   easiest decision. Short, human, and about them rather than about us. */
const PB_SUBJECT = {
  pb_prop:  'About the place you were looking at',
  pb_buyer: 'Your search on the Gulf Coast',
  pb_seller:'What your home is worth',
  pb_oh:    'Thanks for coming by today',
  pb_quiet: 'New listings, nothing else',
  pb_back:  'Good to see you back',
};

function pbSteps(pb) {
  const out = [];
  const mk = (st, i, suffix, type, subject, body) => ({
    /* \u26a0 The id must be STABLE across restarts. drip.done stores these, so anything
       built from Date.now() would come back different after a deploy and every
       message would send a second time. Index into a fixed list is stable. */
    id: 'pbdef:' + pb.id + ':' + i + (suffix || ''),
    day: Number(st.d) || 0,
    type, subject, body,
  });

  /* \u26a0 THE INSTANT OPENER. Nine of the ten built-in sequences open with a TEXT step,
     and texting is never automated here - so out of the box the day-0 send was
     nothing at all, on every funnel that matters. Speed to lead was the entire point
     and it would have shipped doing nothing.

     So when a sequence opens with a text, the same words also go out immediately as
     an email, and the agent STILL gets the reminder to text or call. The person hears
     something within the minute; the human contact still happens on top. The copy is
     short and question-led, which is how a first email should read anyway. */
  const first = pb.steps && pb.steps[0];
  if (first && first.ch === 'sms' && Number(first.d || 0) === 0) {
    out.push(mk(first, 0, 'e', 'email',
      PB_SUBJECT[pb.id] || 'Thanks for getting in touch',
      first.t || ''));
  }

  (pb.steps || []).forEach((st, i) => {
    out.push(mk(st, i, '',
      st.ch === 'email' ? 'email' : 'task',
      st.s || (st.ch === 'email' ? 'Following up' : 'Reach out'),
      /* \u26a0 sms stays a TASK, never an automated send. Texting without prior written
         consent carries a penalty per message. Same rule the CRM applies. */
      st.ch === 'sms' ? 'Text them: ' + (st.t || '') : (st.t || '')));
  });
  return out;
}

/* Every default, keyed the way pickSequenceFor wants them. Built once. */
let PB_LIVE = null;
function livePlaybooks() {
  if (PB_LIVE) return PB_LIVE;
  PB_LIVE = (PLAYBOOK_DEFAULTS || []).map(playbookToCampaign).filter(Boolean);
  return PB_LIVE;
}

/* Resolves a campaign id to a campaign, checking the broker's own first and then the
   built-ins. \u26a0 The sweep needs this too - a lead enrolled on a default would
   otherwise find no campaign and quietly stall forever. */
async function campaignById(id, list) {
  if (!id) return null;
  const own = (list || []).find(c => c && c.id === id);
  if (own) return own;
  return livePlaybooks().find(c => c.id === id) || null;
}

/* ---------- what the site calls a source vs what a playbook matches on ----------
   \u26a0 THESE DID NOT LINE UP AND IT PUT A SELLER ON A BUYER SEQUENCE. The quiz writes
   source 'quiz-seller'; the seller playbook matches on 'value'. No exact match, so it
   fell through to the "every new lead" catch-all - which is the BUYER opener. A seller
   asking what their home is worth was emailed "are you already local, or would this be
   a move down here?".

   Caught by the broker on the first live test, not by me. Anything added to LT_SRC in
   the client belongs here too. */
const SOURCE_TO_TRIGGER = {
  'quiz-seller':  'value',
  'cash-offer':   'value',       // still a seller, just a different doorway
  'quiz-buyer':   'new',
  'quiz':         'new',
  'listing':      'listing',
  'open-house':   'open-house',
  'exit-intent':  'exit-intent',
  'alerts':       'exit-intent', // asked to hear about new listings
  'reactivated':  'reactivated',
};

function triggerForSource(src) {
  const k = String(src || '').toLowerCase().trim();
  if (SOURCE_TO_TRIGGER[k]) return SOURCE_TO_TRIGGER[k];
  /* \u26a0 Imported and referral sources - 'remax.com', 'propertyboost', 'manual add',
     'organic website' - have no funnel behind them. They fall to the catch-all
     deliberately rather than being force-fitted to a story we do not know. */
  return k;
}

async function pickSequenceFor(lead) {
  if (!lead || lead.unsubscribed) return null;
  if (lead.drip && lead.drip.campaignId && !lead.drip.stopped) return null;
  let list = [];
  try { list = (await getSetting('settings:dripCampaigns')) || []; } catch (e) { list = []; }
  if (!Array.isArray(list)) list = [];
  const src = triggerForSource(lead.source);

  /* \u26a0 A seller who says they are only curious must not get the same run as one who
     says "I am ready now". Same doorway, completely different person: chase the
     curious one and you lose them, and they are the group most likely to be early
     enough to actually win. The built-ins already contain the right sequence for
     them - "Seller who is not ready yet", which opens at day 30 with "No pitch. You
     asked what the place was worth." It was unreachable because it matches on type
     rather than source. This is what reaches it. */
  const q = lead.quiz || {};
  const sit = Array.isArray(q.situation) ? q.situation.map(x => String(x).toLowerCase()) : [];
  const curious = q.timeline === 'looking' || sit.includes('just curious');
  if (curious && (lead.type === 'seller' || src === 'value')) {
    const slow = livePlaybooks().find(c => c.id === 'pbdef:pb_seller_slow');
    /* \u26a0 The broker's own beats the built-in here too, if he has written one. */
    const own = list.find(c => c && !c.paused && String(c.trigger).toLowerCase() === 'value-curious');
    if (own || slow) return own || slow;
  }

  const match = pool => pool.find(c => c && !c.paused && c.trigger && c.trigger !== 'manual'
                                    && String(c.trigger).toLowerCase() === src)
                     || pool.find(c => c && !c.paused && c.trigger === 'new');

  /* the broker's own, then the built-in floor */
  return match(list) || match(livePlaybooks()) || null;
}

/* ---------- the drip sweep (server 137) ----------
   \u26a0 THIS IS WHAT MAKES FIVE MINUTES POSSIBLE. Until now the only thing that advanced
   a sequence was POST /api/drip/tick, which the CRM calls when an agent loads it. So a
   lead arriving at 2am - or at 2pm while everyone is out showing houses - got nothing
   until somebody happened to open a browser. A speed-to-lead promise that depends on a
   tab being open is not a promise.

   Same shape as claimSweep: in-process setInterval, deadlines read off the record, no
   session. \u26a0 It deliberately does NOT filter by agent. The session-bound route had to,
   because it was acting as somebody; this is the house acting on its own behalf. */
/* \u26a0 Proof the timer is alive. Without this the only way to tell a sweep that is not
   running from a sweep that ran and found nothing was to read the host logs, which is
   not something the broker can do. */
let DRIP_RUNS = 0, DRIP_LAST_AT = null, DRIP_LAST_SENT = 0, DRIP_LAST_ERR = '';

async function dripSweep() {
  DRIP_RUNS++;
  DRIP_LAST_AT = new Date().toISOString();
  DRIP_LAST_SENT = 0;
  if (!supabase || !mailer) {
    DRIP_LAST_ERR = !supabase ? 'no database connection' : 'no mail sender configured';
    return;
  }
  DRIP_LAST_ERR = '';
  try {
    let campaigns = [];
    try { campaigns = (await getSetting('settings:dripCampaigns')) || []; } catch (e) { campaigns = []; }
    if (!Array.isArray(campaigns)) campaigns = [];
    /* \u26a0 Do NOT bail when the broker has built nothing. The built-in openers are live
       sequences now, so an empty list is the normal state, not an idle one. This
       early return is what would have made "works out of the box" ship inert. */
    const { data, error } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    if (error) { console.error('[drip sweep] read failed:', error.message); return; }
    const now = Date.now();
    let sent = 0;

    /* \u26a0 Resolved ONCE per sweep, not per lead - a lookup inside the loop would hit the
       database once for every lead every minute. Used only when a lead has no assigned
       agent name, so the email is still signed by a human. */
    let sweepBrokerName = '';
    try {
      const { data: ags } = await supabase.from('agents')
        .select('name,role,active').eq('role', 'broker');
      const b = (ags || []).find(a => a.active !== false);
      sweepBrokerName = (b && b.name) || '';
    } catch (e) {}

    for (const row of (data || [])) {
      const lead = row.value;
      if (!lead || !lead.drip || !lead.drip.campaignId || lead.drip.stopped) continue;
      if (lead.unsubscribed) continue;
      /* \u26a0 Through the resolver, not a plain find(): a lead enrolled on a built-in
         opener is not in the broker's own list and would otherwise stall forever
         with no error anywhere. */
      const camp = await campaignById(lead.drip.campaignId, campaigns);
      if (!camp || camp.paused) continue;

      const due = dripDue(lead, camp, now);
      if (!due.length) continue;

      let changed = false;
      for (const step of due) {
        /* \u26a0 A task step is a reminder for the AGENT and must never be mailed to the
           lead. The session route pushes it to a task list; here there is nobody to
           hand it to, so it is marked done and left for the CRM to surface. Sending
           it would post "Call them. Six days, no reply" to the client. */
        if (step.type !== 'email') {
          lead.drip.done = (lead.drip.done || []).concat(step.id);
          changed = true;
          continue;
        }
        if (!lead.email) continue;
        {
          /* \u26a0 Same footer the session route sends: real address and a working
             unsubscribe. This one has a statutory penalty attached to getting it
             wrong, and an automated sender is exactly where it would get forgotten. */
          const unsub = PUBLIC_ORIGIN + '/unsub/' + lead.id + '.' + unsubToken(lead.id);
          /* \u26a0 {agent} is a PERSON. Falling back to the brokerage name signed the email
             "Avani & Co Real Estate Southern Sands" and opened it "it's Avani & Co
             Real Estate Southern Sands" - which reads as a machine, in the one message
             whose whole job is to sound like somebody wrote it. Assigned agent first,
             then the broker, and only then the company. */
          const agent = { name: lead.assignedAgentName || sweepBrokerName || BROKERAGE_NAME };
          try {
            await mailer.sendMail({
              /* \u26a0 marketing:true, or this goes out from the TRANSACTIONAL sender -
                 the same address password resets and claim alerts use. Automated
                 follow-up burning that domain's reputation is how the mail that HAS
                 to arrive stops arriving. */
              marketing: true,
              to: lead.email,
              subject: dripClean(dripFill(step.subject, lead, agent), 'subject'),
              /* \u26a0 The phone number is not optional. Alabama requires real estate
                 advertising to identify the brokerage, and the broker's instruction is
                 that a contact number goes on anything that goes out. The session-side
                 drip already carried it; this one did not, so the automated sends were
                 the only mail leaving without a way to phone back. */
              text: dripClean(dripFill(step.body, lead, agent), 'body')
                  + '\n\n\u2014\n' + (agent.name ? agent.name + '\n' : '')
                  + BROKERAGE_NAME + '\n'
                  + BROKERAGE_PHONE + '\n'
                  + BROKERAGE_ADDRESS + '\n\n'
                  + 'Unsubscribe: ' + unsub + '\n',
            });
            sent++;
          } catch (e) { console.error('[drip sweep] send failed:', e.message); continue; }
        }
        /* \u26a0 dripDue decides what is outstanding from lead.drip.done - an array of
           step IDS - and ignores lead.drip.step entirely. Advancing `step` marks
           nothing as done, so the same message would go out again on the next tick,
           and the next, once a minute forever. Record the id. */
        lead.drip.done = (lead.drip.done || []).concat(step.id);
        lead.drip.lastAt = new Date().toISOString();
        changed = true;
      }
      if (changed) await setSetting(row.key, lead);
    }
    DRIP_LAST_SENT = sent;
    if (sent) console.log('[drip sweep] sent ' + sent + ' message(s)');
  } catch (e) { DRIP_LAST_ERR = e.message; console.error('[drip sweep]', e.message); }
}

/* \u26a0 Every minute, so the day-0 message lands inside the five-minute window rather
   than whenever somebody next happens to sign in. */
setInterval(() => { dripSweep().catch(() => {}); }, 60 * 1000);

/* ---------- Settings > Check the follow-up system ----------
   \u26a0 Built for the same reason as the MLS feed prober: three rounds were spent
   guessing why no follow-up arrived, because from the outside a sequence that never
   enrolled, one that enrolled but has nothing due, and one that tried to send and was
   refused all look identical - silence. This asks the system instead of reasoning
   about it. A dashboard is not a source of truth. */
app.get('/api/drip/status', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });

  let own = [];
  try { own = (await getSetting('settings:dripCampaigns')) || []; } catch (e) {}
  if (!Array.isArray(own)) own = [];
  const built = livePlaybooks();

  const out = {
    ok: true,
    mailer: !!mailer,
    marketingReady: MARKETING_READY,
    marketingFrom: MARKETING_READY ? RESEND_MARKETING_FROM : RESEND_FROM,
    sweepRuns: DRIP_RUNS,
    sweepLastAt: DRIP_LAST_AT,
    sweepLastSent: DRIP_LAST_SENT,
    sweepLastError: DRIP_LAST_ERR,
    ownSequences: own.length,
    builtInSequences: built.length,
    leads: [],
  };

  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    const rows = (data || []).map(r => r.value).filter(Boolean)
      .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
      .slice(0, 5);
    const now = Date.now();
    for (const l of rows) {
      const campId = l.drip && l.drip.campaignId;
      const camp = campId ? await campaignById(campId, own) : null;
      let due = 0;
      try { due = camp ? dripDue(l, camp, now).length : 0; } catch (e) {}
      out.leads.push({
        name: l.name || '(no name)',
        source: l.source || '',
        hasEmail: !!l.email,
        unsubscribed: !!l.unsubscribed,
        lane: l.lane || 'steady',
        enrolled: !!campId,
        sequence: camp ? camp.name : (campId ? 'UNKNOWN id ' + campId : null),
        stopped: !!(l.drip && l.drip.stopped),
        sentSoFar: (l.drip && Array.isArray(l.drip.done)) ? l.drip.done.length : 0,
        dueNow: due,
        wouldMatch: campId ? null : ((await pickSequenceFor(l)) || {}).name || 'nothing',
      });
    }
  } catch (e) { out.leadsError = e.message; }

  res.json(out);
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
  const { name, email, phone, message, source, listingLabel, campaign } = req.body || {};
  // where they came from belongs in the alert - it is the first thing worth knowing
  const camp = campaignLabel(cleanCampaign(campaign));

  /* ---------- SPEED TO LEAD: attach the follow-up, unconditionally ----------
     \u26a0 This runs for EVERY new lead. It used to sit inside the agent-notification
     branch, gated on there being an assigned agent with alerts enabled whose address
     differed from the notification address - so an unassigned lead, or one belonging
     to the broker himself, was never enrolled. It looked correct in review and did
     nothing on the first live test.

     Enrolment is not a notification concern. Nothing below this may gate it.

     \u26a0 It does NOT set firstTouchAt, and must never be changed to. The automated email
     is an opener, not a conversation - the agent's own call is still owed within the
     hour, and firstTouchAt is what proves it happened. Wire this to firstTouchAt and
     the contact deadline silently stops meaning anything. */
  try {
    const leadKey = 'lead:' + (req.body || {}).id;
    const rec = await getSetting(leadKey);
    if (rec && !(rec.drip && rec.drip.campaignId && !rec.drip.stopped)) {
      const seq = await pickSequenceFor(rec);
      if (seq) {
        rec.drip = { campaignId: seq.id, step: 0,
                     startedAt: new Date().toISOString(), stopped: false };
        const ok = await setSetting(leadKey, rec);
        /* \u26a0 setSetting returns false on failure rather than throwing. An enrolment
           reported to the log but never written is exactly the class of bug this
           project keeps paying for. */
        if (ok === false) console.error('[drip] enrolment WRITE FAILED for ' + leadKey);
        else console.log('[drip] ' + (rec.name || leadKey) + ' enrolled on "' + seq.name + '" at arrival');
      } else {
        console.warn('[drip] no sequence matched source "' + (rec.source || '') + '" - nothing will be sent');
      }
    } else if (!rec) {
      console.warn('[drip] no lead record at ' + leadKey + ' - cannot enrol');
    }
  } catch (e) { console.error('[drip] enrolment failed:', e.message); }

  try {
    await mailer.sendMail({
      to: notifyTo,
      subject: `New lead: ${name || 'Unknown'} (${source || 'website'})`,
      text: [
        `Name: ${name || ''}`,
        `Email: ${email || ''}`,
        `Phone: ${phone || ''}`,
        `Source: ${source || ''}`,
        (req.body || {}).id
          ? `Claim it: ${req.protocol}://${req.get('host')}/claim/`
            + encodeURIComponent(req.body.id) + '/' + claimToken(req.body.id)
          : '',
        camp ? `Came from: ${camp}` : null,
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
                  text: speedToLeadSms(req.body || {}),
                });
                console.log(`[lead notification] text sent to ${prof.smsAddress}`);
              } catch (e) {
                console.warn(`[lead notification] text FAILED to ${prof.smsAddress}: ${e.message}`);
              }
            }
            /* ⚠ The subject line IS the notification on a lock screen, so the
               timeline belongs in it. "New lead: Dawn Whitfield" and "READY NOW
               — Dawn Whitfield" get opened at different speeds. */
            const _stlU = URGENCY[((req.body || {}).quiz || {}).timeline];
            /* \u26a0 The window opens when the notification goes out, not when the record
               was written \u2014 you cannot fail to answer something you were never told
               about. Stored on the lead so the sweep survives a restart. */
            try {
              const _lk = 'lead:' + (req.body || {}).id;
              const _l = await getSetting(_lk);
              if (_l && !_l.claimedBy && !_l.claimDue) {
                _l.claimDue = claimDeadline(new Date());
                _l.assignedAgentName = ag.name || '';
                /* \u26a0 Enrolment used to live HERE and it was wrong. This block sits four
                   conditions deep - there must be an assigned agent, the agent must be
                   active with an email, email alerts must be on, AND the agent's address
                   must differ from the notification address. That last one alone excludes
                   the broker, who is usually both. So on a real test the lead arrived, the
                   alert sent, and no sequence was ever attached. Enrolment has nothing to
                   do with notifying an agent; it is now done unconditionally further up. */
                await setSetting(_lk, _l);
              }
            } catch (e) { console.error('[claim] could not set the window:', e.message); }
            const extra = [ag.email];
            for (const to of extra) {
              await mailer.sendMail({
                to,
                subject: (_stlU ? _stlU.label + ' \u2014 ' : 'New lead: ') + (name || 'Unknown'),
                html: speedToLeadHtml(req.body || {}, `${req.protocol}://${req.get('host')}`),
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
  /* ⚠ This route had NO session check. Anyone who knew the path could spend the
     brokerage's Anthropic budget from anywhere. Every other AI route requires a
     session; this one was written before that pattern settled and was missed. */
  const sess = await requireSession(req, res); if (!sess) return;
  if (!aiRateOk(sess.agentId)) return res.status(429).json({ error: 'Too many drafts today.' });
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

/* ==================== THE ASSISTANT INSIDE THE CRM (server 109) ====================
   Three jobs: draft a follow-up for one lead, write a listing description from the
   feed, and answer questions about the agent's own book.

   ⚠ guardTopic() above is an INBOUND guard. It catches a visitor asking a steering
   question and deflects before Claude is ever called. These routes need the opposite.
   The agent's request is legitimate; the risk is in what comes BACK. Marketing copy
   is exactly where fair housing violations live — "perfect for families", "safe
   neighborhood", "walking distance to good schools" — and this copy goes out under
   the brokerage's name and the agent's licence. So the scan runs on the OUTPUT.

   ⚠ It FLAGS, it does not silently rewrite. An agent who never sees what was caught
   learns nothing and will write the same phrase by hand next week.

   ⚠ Nothing here sends. Every route returns a draft. */

const FH_COPY = [
  { re: /\bfamily[\s-]?friendly\b/i,                                    why: 'familial status' },
  { re: /\b(perfect|great|ideal|good|wonderful)\s+(for\s+)?(a\s+)?(famil(y|ies)|kids|children)\b/i, why: 'familial status' },
  { re: /\b(no|not for)\s+(kids|children)\b/i,                          why: 'familial status' },
  { re: /\b(safe|secure|low[\s-]?crime|crime[\s-]?free)\s+(area|neighborhood|neighbourhood|community|street)\b/i, why: 'race / national origin (coded)' },
  { re: /\b(good|great|top|excellent|best|desirable)\s+school(s|\sdistrict)?\b/i, why: 'familial status / race (coded)' },
  { re: /\bwalking distance to\s+(school|church)/i,                     why: 'familial status / religion' },
  { re: /\b(church|churches|synagogue|mosque|temple|congregation|parish)\b/i, why: 'religion' },
  { re: /\b(christian|catholic|jewish|muslim|hindu)\b/i,                why: 'religion' },
  { re: /\b(exclusive|private|restricted|select)\s+(community|neighborhood|neighbourhood|enclave)\b/i, why: 'race / national origin (coded)' },
  { re: /\b(adult|senior|retiree|55\+)\s+(only|community|living)\b/i,   why: 'familial status / age — lawful only for registered HOPA housing' },
  { re: /\b(young professionals|empty nesters|singles|newlyweds|bachelor)\b/i, why: 'familial status / age' },
  { re: /\b(quiet|mature|established|traditional)\s+(neighborhood|neighbourhood|community)\b/i, why: 'familial status (coded)' },
  { re: /\b(ethnic|racial|integrated|diverse)\s+(area|neighborhood|neighbourhood|community)\b/i, why: 'race / national origin' },
  { re: /\b(handicap|disabled|wheelchair)[\s-]?(accessible|friendly)?\b/i, why: 'disability — describe the feature, not who it suits' },
  { re: /\bmust be (employed|working)\b/i,                              why: 'source of income' },
  { re: /\bno (section 8|vouchers|housing assistance)\b/i,              why: 'source of income' },
];

/* Returns what tripped, with the protected class named. The agent sees the reason,
   not just a red box, because the reason is the part that transfers. */
function fhScan(text) {
  const t = String(text || '');
  const hits = [];
  FH_COPY.forEach(({ re, why }) => {
    const m = t.match(re);
    if (m && !hits.some(h => h.phrase.toLowerCase() === m[0].toLowerCase())) {
      hits.push({ phrase: m[0], why });
    }
  });
  return hits;
}

/* Figures invented in a follow-up are worse than in an article — an article is read,
   a follow-up is relied on. Same scan the article drafter uses. */
function figureScan(text) {
  return String(text || '').match(/\$[\d,]+(\.\d+)?|\b\d+(\.\d+)?\s?%/g) || [];
}

/* ⚠ In memory on purpose. This exists to stop a loop or a stuck button burning
   the API budget, not to stop a determined attacker, and it resets on restart.
   A per-agent KV counter would survive restarts and cost a round trip per call. */
const AI_CALLS = new Map();
const AI_DAILY_CAP = 120;
function aiRateOk(agentId) {
  const day = new Date().toISOString().slice(0, 10);
  const key = day + ':' + agentId;
  const n = (AI_CALLS.get(key) || 0) + 1;
  AI_CALLS.set(key, n);
  if (AI_CALLS.size > 500) {
    for (const k of AI_CALLS.keys()) if (!k.startsWith(day)) AI_CALLS.delete(k);
  }
  return n <= AI_DAILY_CAP;
}

/* ⚠ Ownership is decided here, on the real session, never from the request body.
   Same rule as segmentLeads(): the client-side picker is convenience. And note it
   reads sess.agentId — under View as, the broker is still the broker, which is the
   correct answer for a route that reaches personal data. */
async function loadOwnLead(sess, leadId) {
  const id = String(leadId || '').slice(0, 80);
  if (!id) return null;
  const lead = await getSetting('lead:' + id);
  if (!lead) return null;
  if (!isStaff(sess) && lead.assignedAgentId !== sess.agentId) {
    console.warn(`[ai] agent ${sess.agentId} blocked drafting for lead owned by ${lead.assignedAgentId || '(nobody)'}`);
    return null;
  }
  return lead;
}

const AI_VOICE = [
  `You write for ${BROKERAGE_NAME}, a brokerage on the Alabama Gulf Coast.`,
  '',
  'Voice: direct, specific, unhurried. Short sentences. Write like a person who',
  'knows the area, not like marketing. No "nestled", no "dream home", no "stunning",',
  'no "must see", no exclamation marks. American English.',
  '',
  'HARD RULES — these are licence conditions, not style preferences:',
  '1. Never describe an AREA or WHO LIVES THERE. No schools, no safety, no crime, no',
  '   churches, no "family friendly", no "quiet neighborhood", no demographics of any',
  '   kind. Describe the PROPERTY and the FACTS you were given. This is fair housing',
  '   and it does not require intent to be a violation.',
  '2. Never invent a number. No prices, sizes, fees, rates, days on market or',
  '   percentages unless the figure was given to you above. If you need one you do',
  '   not have, leave it out or say it depends.',
  '3. Never give legal, tax, lending or insurance advice, and never opine on what a',
  '   property is worth or what someone should offer. Say who to ask.',
  '4. Never state who pays commission or that representation is free.',
].join('\n');

/* ---------- 1. Draft a follow-up for one lead ---------- */
app.post('/api/ai/followup', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI is not configured. Set ANTHROPIC_API_KEY.' });
  if (!aiRateOk(sess.agentId)) return res.status(429).json({ error: 'That is a lot of drafts today. Try again tomorrow.' });

  const b = req.body || {};
  const lead = await loadOwnLead(sess, b.leadId);
  if (!lead) return res.status(404).json({ error: 'Not your lead, or no longer there.' });

  const channel = b.channel === 'text' ? 'text' : 'email';
  const note = String(b.note || '').trim().slice(0, 400);

  /* ⚠ Deliberately NOT sending email or phone to the API. Nothing in the drafting
     job needs contact details, and the less that leaves the building the better. */
  const days = lead.createdAt
    ? Math.round((Date.now() - new Date(lead.createdAt).getTime()) / 86400000) : null;
  const viewed = Array.isArray(lead.viewedListings)
    ? lead.viewedListings.slice(0, 6).map(v => v.label || v.address || v).join('; ') : '';
  const crit = lead.criteria || lead.searchCriteria || null;

  const facts = [
    'First name: ' + String(lead.name || '').split(' ')[0],
    'Stage: ' + (lead.stage || 'New'),
    'Lane: ' + (lead.lane || 'steady'),
    lead.score ? 'Engagement score: ' + lead.score : '',
    days !== null ? 'On the books: ' + days + ' days' : '',
    lead.source ? 'Came from: ' + lead.source : '',
    lead.listingLabel ? 'Enquired about: ' + lead.listingLabel : '',
    lead.fromArticle ? 'Read the article: ' + lead.fromArticle : '',
    viewed ? 'Listings they have looked at: ' + viewed : '',
    crit ? 'What they are looking for: ' + JSON.stringify(crit).slice(0, 400) : '',
    lead.message ? 'What they originally said: ' + String(lead.message).slice(0, 400) : '',
    note ? 'The agent adds: ' + note : '',
  ].filter(Boolean).join('\n');

  const shape = channel === 'text'
    ? 'Write a TEXT MESSAGE. Under 320 characters. No signature block, no subject.'
    : 'Write an EMAIL BODY only — no subject line, no signature block. Three to five sentences.';

  const system = AI_VOICE + '\n\n' + [
    'You are drafting a follow-up from ' + (sess.name || 'the agent') + ' to one specific',
    'person who is already in this agent\'s database. It must read as though the agent',
    'wrote it after looking at the record — reference something real from the facts',
    'below. A message that could have been sent to anybody is a failure.',
    '',
    shape,
    'Return ONLY the message text. No preamble, no quotes around it, no explanation.',
  ].join('\n');

  try {
    const draft = (await callClaude(system, [{ role: 'user', content: facts }], 600)).trim();
    const fh = fhScan(draft);
    const figures = figureScan(draft);
    if (fh.length) console.warn(`[ai/followup] fair-housing flag for ${sess.agentId}: ${fh.map(h => h.phrase).join(', ')}`);
    console.log(`[ai/followup] ${channel} draft for lead ${lead.id} by ${sess.name || sess.agentId}`);
    res.json({ ok: true, draft, channel, fairHousing: fh, figuresFound: figures,
      lead: { id: lead.id, name: lead.name, email: lead.email || '', phone: lead.phone || '' } });
  } catch (e) {
    console.error('[ai/followup]', e.message);
    res.status(500).json({ error: 'Could not draft that right now.' });
  }
});

/* ---------- 2. Write a listing description from the feed ---------- */
app.post('/api/ai/listing-copy', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI is not configured. Set ANTHROPIC_API_KEY.' });
  if (!aiRateOk(sess.agentId)) return res.status(429).json({ error: 'That is a lot of drafts today. Try again tomorrow.' });

  const key = String((req.body || {}).mlsKey || '').trim().slice(0, 60);
  const kind = ['flyer', 'social', 'listing'].includes((req.body || {}).kind) ? req.body.kind : 'listing';
  if (!key) return res.status(400).json({ error: 'Which listing? Paste the MLS number.' });

  let r;
  try {
    const url = `OData/${BRIDGE_DATASET}/Property`;
    const data = await bridgeGet(url, {
      $filter: `ListingKey eq '${key.replace(/'/g, "''")}' or ListingId eq '${key.replace(/'/g, "''")}'`,
      $top: 1,
    });
    r = (data.value || [])[0];
  } catch (e) {
    console.error('[ai/listing-copy] feed:', e.message);
    return res.status(502).json({ error: 'Could not reach the MLS feed.' });
  }
  if (!r) return res.status(404).json({ error: 'No listing with that number in the feed.' });

  const facts = [
    'Address: ' + (r.UnparsedAddress || ''),
    'City: ' + (r.City || ''),
    r.ListPrice ? 'List price: $' + Number(r.ListPrice).toLocaleString() : '',
    r.BedroomsTotal ? 'Bedrooms: ' + r.BedroomsTotal : '',
    r.BathroomsTotalInteger ? 'Bathrooms: ' + r.BathroomsTotalInteger : '',
    r.LivingArea ? 'Living area: ' + r.LivingArea + ' sq ft' : '',
    r.YearBuilt ? 'Year built: ' + r.YearBuilt : '',
    r.LotSizeAcres ? 'Lot: ' + r.LotSizeAcres + ' acres' : '',
    r.PropertySubType ? 'Type: ' + r.PropertySubType : '',
    r.SubdivisionName ? 'Subdivision: ' + r.SubdivisionName : '',
    r.PublicRemarks ? 'Existing remarks from the listing agent: ' + String(r.PublicRemarks).slice(0, 1500) : '',
  ].filter(Boolean).join('\n');

  const shape = {
    listing: 'Write PUBLIC REMARKS for the MLS. 120 to 180 words, one paragraph.',
    flyer:   'Write flyer copy. Two short paragraphs, 60 to 90 words total.',
    social:  'Write a social post. Under 60 words. No hashtag spam — at most two.',
  }[kind];

  const system = AI_VOICE + '\n\n' + shape + '\n'
    + 'Use only the facts below. If a fact is missing, leave it out rather than guessing.\n'
    + 'Return ONLY the copy. No preamble, no heading.';

  try {
    const draft = (await callClaude(system, [{ role: 'user', content: facts }], 700)).trim();
    const fh = fhScan(draft);
    if (fh.length) console.warn(`[ai/listing-copy] fair-housing flag for ${sess.agentId}: ${fh.map(h => h.phrase).join(', ')}`);
    /* ⚠ Same IDX condition as everywhere else — if this is another brokerage's
       listing, the credit travels with the copy. */
    const credit = listingCredit(r);
    console.log(`[ai/listing-copy] ${kind} for ${key} by ${sess.name || sess.agentId}`);
    res.json({ ok: true, draft, kind, credit, fairHousing: fh,
      listing: { address: r.UnparsedAddress || '', price: r.ListPrice || null, key: r.ListingKey || key } });
  } catch (e) {
    console.error('[ai/listing-copy]', e.message);
    res.status(500).json({ error: 'Could not write that right now.' });
  }
});

/* ---------- 3. Ask a question about your own book ---------- */
app.post('/api/ai/ask', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI is not configured. Set ANTHROPIC_API_KEY.' });
  if (!aiRateOk(sess.agentId)) return res.status(429).json({ error: 'That is a lot of questions today. Try again tomorrow.' });

  const q = String((req.body || {}).question || '').trim().slice(0, 500);
  if (!q) return res.status(400).json({ error: 'Ask something.' });

  let all = [];
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
    all = (data || []).map(x => x.value).filter(Boolean);
  } catch (e) { return res.status(500).json({ error: 'Could not read leads.' }); }

  /* ⚠ The scoping rule, applied server-side and not negotiable from the client.
     An agent asking "who has gone quiet" gets their own book and nobody else's. */
  const staff = isStaff(sess);
  const mine = all.filter(l => staff || l.assignedAgentId === sess.agentId);

  /* ⚠ No email addresses, no phone numbers, no message bodies leave the building.
     Everything the question needs is structural. Name is included because the answer
     is useless without it; contact details are not, so they stay here. */
  const now = Date.now();
  const rows = mine.slice(0, 250).map(l => ({
    name: l.name || '(no name)',
    stage: l.stage || 'New',
    lane: l.lane || 'steady',
    score: l.score || 0,
    type: l.type || '',
    source: l.source || '',
    city: (l.criteria && (l.criteria.city || (l.criteria.cities || [])[0])) || '',
    daysOnBooks: l.createdAt ? Math.round((now - new Date(l.createdAt).getTime()) / 86400000) : null,
    daysSinceTouch: l.lastTouchAt ? Math.round((now - new Date(l.lastTouchAt).getTime()) / 86400000) : null,
    unsubscribed: !!l.unsubscribed,
  }));

  const system = [
    'You answer questions about a real estate agent\'s own lead list. You are given',
    'the whole list as JSON. Answer only from it.',
    '',
    'Be concrete. Name people. Give counts. If the answer is a list, keep it short and',
    'ordered by whatever the question implies matters.',
    'If the data does not contain the answer, say so plainly rather than estimating.',
    'Never invent a lead, a number, or a date.',
    '',
    'You are looking at structure, not contact details — you do not have their email',
    'or phone, and you should not pretend to.',
    '',
    'Do not characterise areas, schools, safety or who lives somewhere, even if asked.',
    'Do not advise on price, contracts, tax or law.',
    'Plain prose. No headings. Under 200 words unless a list genuinely needs more.',
  ].join('\n');

  const payload = `Question: ${q}\n\nThe list (${rows.length} of ${mine.length} shown):\n`
    + JSON.stringify(rows);

  try {
    const answer = (await callClaude(system, [{ role: 'user', content: payload }], 900)).trim();
    console.log(`[ai/ask] "${q.slice(0, 60)}" over ${rows.length} leads for ${sess.name || sess.agentId}`);
    res.json({ ok: true, answer, considered: rows.length, total: mine.length,
      truncated: mine.length > rows.length });
  } catch (e) {
    console.error('[ai/ask]', e.message);
    res.status(500).json({ error: 'Could not answer that right now.' });
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

app.get('/api/health', async (req, res) => {
  /* \u26a0 Never cached. This route exists to answer "what is actually running", and a
     cached answer to that question is worse than no answer \u2014 it sent us chasing a
     deploy that had already worked. */
  res.set('Cache-Control', 'no-store, must-revalidate');
  res.json({
    ok: true,
    serverVersion: 'v144',
    routes: ['market-stats','mls-fields','search','listings'],
    brokerage: BROKERAGE_NAME,
    database: !!supabase,
    mlsDataset: process.env.BRIDGE_DATASET || 'gcmls2',
    mlsConfigured: !!(process.env.BRIDGE_SERVER_TOKEN && process.env.BRIDGE_DATASET),
    emailConfigured: !!mailer,
    marketingDomainReady: MARKETING_READY,
    aiConfigured: !!ANTHROPIC_API_KEY,
    /* ⚠ The RAW stored value, plus what it resolves to. When robots.txt disagreed
       with the switch there was no way to tell whether the write had failed, the
       read was wrong, or a cache was stale. Now you can see the value itself. */
    siteMode: await getSetting('settings:siteMode'),
    sitePrivate: await siteIsPrivate(),
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


/* ==================== AREA PAGES (server 111) ====================
   The free-traffic gap. Indexable page types were: homepage, agent bios, /insights,
   and articles. Nothing on this site answered "homes for sale in Gulf Shores" — the
   highest-intent unpaid search in this market — so that traffic went to Zillow.

   \u26a0 SCALED CONTENT. Google's spam policy targets pages generated at volume to rank.
   The defence here is not word count, it is that every page is anchored to LIVE
   inventory from the feed: real active counts, a real price range, real property
   types, updated hourly. A page that tells you there are 47 condos in Orange Beach
   between $310k and $1.2m right now is not thin content, and no competitor's
   template can say it. Twelve towns, hand-written intros, no generation loop.

   \u26a0 FAIR HOUSING. Area pages are exactly where steering language appears — "great
   for families", "safe", "good schools". Every intro below is about GEOGRAPHY and
   HOUSING STOCK only, and each one is run through fhScan() at boot so a careless
   edit later gets caught rather than published. */

const AREAS = [
  { slug:'gulf-shores', name:'Gulf Shores', city:'Gulf Shores',
    blurb:'Gulf-front high-rises along West Beach and East Beach, canal and lagoon homes '
        + 'on the north side, and detached houses inland toward the Foley line. Most of '
        + 'the condo stock sits on Beach Boulevard and West Beach Boulevard.' },
  { slug:'orange-beach', name:'Orange Beach', city:'Orange Beach',
    blurb:'Almost entirely condominium, concentrated on Perdido Beach Boulevard, with '
        + 'the deep-water and Ono Island market handling most of the single-family '
        + 'inventory. Marina and boat-slip properties trade here more than anywhere else '
        + 'on this coast.' },
  { slug:'fort-morgan', name:'Fort Morgan', city:'Fort Morgan',
    blurb:'The peninsula west of Gulf Shores \u2014 low-density, largely stilted beach '
        + 'houses on the Gulf and Mobile Bay sides, with far fewer mid-rise buildings '
        + 'than the towns to the east. Rental-history properties are common.' },
  { slug:'fairhope', name:'Fairhope', city:'Fairhope',
    blurb:'Eastern Shore of Mobile Bay. A walkable older core with early-twentieth-century '
        + 'housing stock, bluff properties overlooking the bay, and newer subdivisions '
        + 'spreading east toward County Road 13 and Highway 181.' },
  { slug:'daphne', name:'Daphne', city:'Daphne',
    blurb:'North of Fairhope on the Eastern Shore, and the closest Baldwin County town '
        + 'to the Mobile causeway. Mostly subdivision single-family, with bay-adjacent '
        + 'properties along Main Street and Highway 98.' },
  { slug:'foley', name:'Foley', city:'Foley',
    blurb:'Inland from the beaches and the largest concentration of new construction in '
        + 'south Baldwin County. Predominantly detached single-family on full lots, with '
        + 'acreage available on the outskirts toward Elberta and Magnolia Springs.' },
  { slug:'spanish-fort', name:'Spanish Fort', city:'Spanish Fort',
    blurb:'At the top of the Eastern Shore where I-10 crosses the delta. Newer '
        + 'subdivision housing, some bay and delta frontage, and the shortest commute in '
        + 'Baldwin County to downtown Mobile.' },
  { slug:'elberta', name:'Elberta', city:'Elberta',
    blurb:'Rural south Baldwin between Foley and the Florida line. Acreage, barndominiums '
        + 'and detached homes on large lots, with far fewer subdivisions than the coast.' },
  { slug:'robertsdale', name:'Robertsdale', city:'Robertsdale',
    blurb:'Central Baldwin County agricultural land and small-lot single-family, with '
        + 'more acreage per dollar than anywhere south of it.' },
  { slug:'perdido-key', name:'Perdido Key', city:'Perdido Key',
    blurb:'The Florida side of the state line \u2014 Gulf-front and sound-side condominium '
        + 'towers along Perdido Key Drive, with a thin strip of detached houses between '
        + 'the two waters.' },
  { slug:'magnolia-springs', name:'Magnolia Springs', city:'Magnolia Springs',
    blurb:'A small river town on the Magnolia River, known for waterfront homes with '
        + 'private docks and the live-oak canopy along Oak Street.' },
  { slug:'bon-secour', name:'Bon Secour', city:'Bon Secour',
    blurb:'Working waterfront on the Bon Secour River between Gulf Shores and Foley. '
        + 'River-frontage properties and small acreage, with commercial seafood still '
        + 'operating on the water.' },
];

/* \u26a0 Boot-time check on our own copy. If somebody edits a blurb later and reaches
   for the language that gets brokerages sued, the log says so on the next restart. */
AREAS.forEach(a => {
  const hits = fhScan(a.blurb + ' ' + a.name);
  if (hits.length) {
    console.error(`[areas] \u26a0 FAIR HOUSING in "${a.name}" copy: `
      + hits.map(h => `"${h.phrase}" (${h.why})`).join(', '));
  }
});

/* The feed is the expensive part and this data barely moves, so one call per town
   per hour. Without this a crawler walking twelve pages hammers Bridge. */
const AREA_CACHE = new Map();
const AREA_TTL = 3600000;

async function areaStats(city) {
  const hit = AREA_CACHE.get(city);
  if (hit && Date.now() - hit.at < AREA_TTL) return hit.data;
  const esc = String(city).replace(/'/g, "''");
  const out = { count: 0, min: null, max: null, beds: {}, types: {}, sample: [] };
  try {
    const d = await bridgeGet(`OData/${BRIDGE_DATASET}/Property`, {
      $filter: `${ACTIVE_ONLY} and contains(City,'${esc}')`,
      $select: 'ListingKey,ListingId,UnparsedAddress,City,ListPrice,BedroomsTotal,'
             + 'BathroomsTotalInteger,LivingArea,PropertySubType,ListOfficeName',
      $top: 200, $orderby: 'ListPrice desc',
    });
    const rows = (d.value || []).filter(r => r.ListPrice > 0);
    out.count = rows.length;
    if (rows.length) {
      const prices = rows.map(r => Number(r.ListPrice)).sort((a, b) => a - b);
      out.min = prices[0];
      out.max = prices[prices.length - 1];
      out.median = prices[Math.floor(prices.length / 2)];
      rows.forEach(r => {
        const t = r.PropertySubType || 'Other';
        out.types[t] = (out.types[t] || 0) + 1;
      });
      /* A handful of real listings, newest-priced-first, each carrying its IDX
         credit. Not a full search result \u2014 the point of the page is the town. */
      out.sample = rows.slice(0, 6).map(r => ({
        key: r.ListingKey || r.ListingId || '',
        addr: r.UnparsedAddress || '',
        price: Number(r.ListPrice),
        beds: r.BedroomsTotal || null,
        baths: r.BathroomsTotalInteger || null,
        sqft: r.LivingArea || null,
        credit: listingCredit(r),
      }));
    }
  } catch (e) {
    console.warn(`[areas] feed failed for ${city}:`, e.message);
  }
  AREA_CACHE.set(city, { at: Date.now(), data: out });
  return out;
}

function money(n) { return '$' + Number(n || 0).toLocaleString('en-US', { maximumFractionDigits: 0 }); }

function areaSeoHtml(a, stats, origin, agentSlug, noindex, articles) {
  const esc = t => String(t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const url = `${origin}/homes/${a.slug}`;
  const q = agentSlug ? `&agent=${encodeURIComponent(agentSlug)}` : '';
  const title = `Homes for sale in ${a.name}, AL`;
  const desc = stats.count
    ? `${stats.count} active listings in ${a.name} right now, from ${money(stats.min)} to `
      + `${money(stats.max)}. Live from Gulf Coast MLS, updated hourly.`
    : `Current listings and market detail for ${a.name} on the Alabama Gulf Coast.`;

  const topTypes = Object.entries(stats.types || {})
    .sort((x, y) => y[1] - x[1]).slice(0, 4);

  const ld = {
    '@context': 'https://schema.org',
    '@type': 'CollectionPage',
    name: title,
    description: desc,
    url,
    about: { '@type': 'Place', name: `${a.name}, Alabama` },
    provider: {
      '@type': 'RealEstateAgent', name: BROKERAGE_NAME, url: origin,
      telephone: BROKERAGE_PHONE, address: BROKERAGE_ADDRESS,
      areaServed: AREAS.map(x => ({ '@type': 'Place', name: x.name })),
    },
  };

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} | ${esc(BROKERAGE_NAME)}</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${url}">${noindex ? '\n<meta name="robots" content="noindex,nofollow">' : ''}
<meta property="og:type" content="website">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${url}">
<script type="application/ld+json">${JSON.stringify(ld)}</script>
<style>
body{margin:0;background:#FBFAF7;color:#141A3C;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:760px;margin:0 auto;padding:38px 22px 70px}
a{color:#C89B4E}
.eb{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#C89B4E;font-weight:700}
h1{font-family:Georgia,serif;font-size:34px;line-height:1.15;font-weight:400;margin:12px 0 14px}
p{font-size:16px;margin:0 0 18px}
.lede{font-size:17px;color:#3D456B}
.nums{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:26px 0 30px}
@media(max-width:560px){.nums{grid-template-columns:1fr 1fr}}
.num{background:#fff;border:1px solid rgba(20,26,60,.1);border-radius:5px;padding:15px 16px}
.num .k{font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;color:#7A8199;font-weight:700}
.num .v{font-family:Georgia,serif;font-size:24px;margin-top:5px;line-height:1.1}
h2{font-family:Georgia,serif;font-size:23px;font-weight:400;margin:34px 0 12px}
.li{display:block;background:#fff;border:1px solid rgba(20,26,60,.1);border-radius:5px;
  padding:14px 16px;margin-bottom:9px;text-decoration:none;color:#141A3C}
.li:hover{border-color:#C89B4E}
.li .a{font-weight:600;font-size:15px}
.li .m{font-size:13px;color:#5A6178;margin-top:3px}
.li .c{font-size:11px;color:#8A90A6;margin-top:6px}
.cta{margin-top:36px;padding:24px;background:#fff;border:1px solid rgba(20,26,60,.1);
  border-left:3px solid #C89B4E;border-radius:4px}
.cta h2{margin:0 0 8px;font-size:22px}
.cta p{font-size:15px;color:#3D456B}
.btn{display:inline-block;background:#C89B4E;color:#241A08;text-decoration:none;
  padding:12px 22px;border-radius:3px;font-weight:700;font-size:13px;
  letter-spacing:.05em;text-transform:uppercase;margin-top:6px}
.near{margin-top:34px;padding-top:22px;border-top:1px solid rgba(20,26,60,.12)}
.near a{display:inline-block;margin:0 14px 9px 0;font-size:14px}
.dis{margin-top:34px;padding:16px 18px;background:#fff;border:1px solid rgba(20,26,60,.12);
  border-radius:4px;font-size:12.5px;line-height:1.6;color:#5A6178}
.ft{margin-top:22px;padding-top:20px;border-top:1px solid rgba(20,26,60,.1);
  font-size:13px;color:#7A8199}
</style></head><body><div class="w">
<div class="eb">Baldwin County &middot; Alabama Gulf Coast</div>
<h1>${esc(title)}</h1>
<p class="lede">${esc(a.blurb)}</p>
${stats.count ? `<div class="nums">
  <div class="num"><div class="k">On the market</div><div class="v">${stats.count}</div></div>
  <div class="num"><div class="k">From</div><div class="v">${money(stats.min)}</div></div>
  <div class="num"><div class="k">Up to</div><div class="v">${money(stats.max)}</div></div>
</div>
<p>Right now there ${stats.count === 1 ? 'is' : 'are'} <strong>${stats.count}</strong> active
${stats.count === 1 ? 'listing' : 'listings'} in ${esc(a.name)}, priced between
${money(stats.min)} and ${money(stats.max)}, with a midpoint around ${money(stats.median)}.
${topTypes.length ? 'Most of it is ' + topTypes.map(([t, n]) =>
  `${esc(t.toLowerCase())} (${n})`).join(', ') + '.' : ''}
These figures come straight from Gulf Coast MLS and are refreshed hourly, so they move
with the market rather than being written once and forgotten.</p>` :
`<p>Live inventory for ${esc(a.name)} is not loading at the moment. Every active listing
is searchable on the main site.</p>`}

${stats.sample.length ? `<h2>A few of them</h2>
${stats.sample.map(s => `<a class="li" href="${origin}/?mls=${encodeURIComponent(s.key)}${q}">
  <div class="a">${esc(s.addr)}</div>
  <div class="m">${money(s.price)}${s.beds ? ' &middot; ' + s.beds + ' bd' : ''}${
    s.baths ? ' &middot; ' + s.baths + ' ba' : ''}${
    s.sqft ? ' &middot; ' + Number(s.sqft).toLocaleString() + ' sq ft' : ''}</div>
  ${s.credit ? `<div class="c">${esc(s.credit)}</div>` : ''}
</a>`).join('')}` : ''}

<div class="cta">
  <h2>Tell us what you are looking for in ${esc(a.name)}</h2>
  <p>Six questions, about a minute. We will email you the ones that fit as they come on
     the market, and stop the moment you say so.</p>
  <a class="btn" href="${origin}/?q=buy${q}">Set up alerts for ${esc(a.name)}</a>
</div>

<div class="near"><div class="eb">Nearby</div><br>
${AREAS.filter(x => x.slug !== a.slug).slice(0, 7).map(x =>
  `<a href="${origin}/homes/${x.slug}${agentSlug ? '?agent=' + encodeURIComponent(agentSlug) : ''}">${esc(x.name)}</a>`).join('')}
</div>

${(articles && articles.length) ? `<div class="near"><div class="eb">Worth reading first</div><br>
${articles.slice(0, 3).map(o =>
  `<a href="${origin}/insights/${o.slug}${agentSlug ? '?agent=' + encodeURIComponent(agentSlug) : ''}">${esc(o.title)}</a>`).join('')}
</div>` : ''}

<div class="dis">${esc(DISCLAIMER_GENERAL)}</div>
<div class="ft">${esc(BROKERAGE_NAME)} &middot; ${esc(BROKERAGE_PHONE)}<br>
${esc(BROKERAGE_ADDRESS)}<br>
<a href="${origin}/">Search every active listing</a> &nbsp;&middot;&nbsp;
<a href="${origin}/insights">Guides</a></div>
</div></body></html>`;
}


/* ==================== CMA DELIVERY (server 117) ====================
   The report itself is produced in RPR. Nothing here analyses anything, adds a cover
   page, or touches the numbers \u2014 the RPR PDF already carries the subject photo, both
   licence numbers, the brokerage details and the "this is not an appraisal" wording
   that Alabama requires. Wrapping our own cover around that would give the seller two
   cover pages and make it look assembled rather than produced.

   What is missing from RPR is the part we own: knowing the seller opened it, and
   having that count toward the lead's score. Opening a valuation on your own house
   three times on a Sunday evening is the strongest buying signal a seller ever gives,
   and it currently vanishes.

   \u26a0 LICENSING, UNRESOLVED. Emailing an RPR PDF to your own client is the intended
   use and nobody would question it. Storing it, serving it from our domain behind a
   token and recording engagement is a different act, and the report also contains
   MLS-derived data reaching us through RPR's licence rather than through Bridge.
   RPR's Terms of Use and RPR support are the places that settle it. Built so it can
   be switched off in one place if the answer comes back differently: delete the two
   routes below and the CRM falls back to plain email with an attachment. */

const CMA_MAX_BYTES = 9 * 1024 * 1024;     // ~12MB base64, under the 14mb json ceiling

function cmaToken(id) {
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('cma:' + id).digest('hex').slice(0, 24);
}

/* ---------- the agent uploads what RPR produced ---------- */

/* ==================== VIDEO PROMOS (server 122) ====================
   A library of videos \u2014 listing walkthroughs, marketing pieces \u2014 and a tracked link
   per person you send one to.

   \u26a0 Nothing is hosted here. The video stays on YouTube or Vimeo, where it is already
   paid for, already transcoded and already served fast. This stores a link and wraps
   it in a page we control so the open can be counted. Hosting video out of this
   Express process would be slow, expensive and pointless.

   \u26a0 The embed URL is BUILT by us from a parsed id, never taken from what was pasted.
   An <iframe src> that a user can set is an open door \u2014 anything from a phishing page
   to a keylogger, framed inside a page carrying the brokerage name. Two providers,
   both matched against a strict pattern, and anything else is refused. */

const VID_PROVIDERS = [
  { key: 'youtube', re: /(?:youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/)|youtu\.be\/)([A-Za-z0-9_-]{6,20})/,
    embed: id => `https://www.youtube-nocookie.com/embed/${id}`,
    watch: id => `https://www.youtube.com/watch?v=${id}`,
    thumb: id => `https://i.ytimg.com/vi/${id}/hqdefault.jpg` },
  { key: 'vimeo',   re: /vimeo\.com\/(?:video\/)?(\d{6,12})/,
    embed: id => `https://player.vimeo.com/video/${id}`,
    watch: id => `https://vimeo.com/${id}`,
    thumb: () => '' },
];

function parseVideo(url) {
  const u = String(url || '').trim();
  for (const p of VID_PROVIDERS) {
    const m = u.match(p.re);
    if (m) return { provider: p.key, videoId: m[1], embed: p.embed(m[1]),
                    watchUrl: p.watch(m[1]), thumb: p.thumb(m[1]) };
  }
  return null;
}

function promoToken(promoId, leadId) {
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('promo:' + promoId + ':' + leadId).digest('hex').slice(0, 24);
}

/* ---------- the library ---------- */
/* ==================== OUTSIDE TOOLS (server 124) ====================
   Asked for a long time ago and never built: tabs for ShowingTime, Redex, Paragon,
   GCMLS, Perchwell. They cannot be embedded \u2014 every one of them sends
   X-Frame-Options or a frame-ancestors policy precisely to stop that, and getting
   round it would mean proxying somebody's authenticated session, which is not
   something to do to an MLS. So they open in a new tab with the saved link.

   \u26a0 The value is small and real: one place to launch from, the same links for
   everybody, and a new agent who does not yet know which of five systems does what.

   \u26a0 Broker writes, everyone reads. An agent adding a link that everyone sees is a
   way to put an arbitrary destination in front of the whole brokerage. */
function cleanLinks(raw) {
  const out = [];
  for (const l of (Array.isArray(raw) ? raw : []).slice(0, 12)) {
    const label = String(l.label || '').slice(0, 24).trim();
    let url = String(l.url || '').slice(0, 400).trim();
    if (!label || !url) continue;
    /* \u26a0 Upgrade http, prepend when there is no scheme at all, and leave anything with
       a different scheme to be rejected below. Prepending blindly turned
       http://x into https://http://x. */
    if (/^http:\/\//i.test(url)) url = 'https://' + url.slice(7);
    else if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) url = 'https://' + url.replace(/^\/*/, '');
    try { const u = new URL(url); if (u.protocol !== 'https:') continue; }
    catch (e) { continue; }
    out.push({ label, url });
  }
  return out;
}


/* ==================== CLEARING THE TEST DATA (server 128) ====================
   Everything in here was seeded to prove the system works. Left in place it makes the
   first real week unreadable: "12 new leads" means nothing if eleven are invented, and
   the counters on Today go back to being numbers nobody trusts.

   \u26a0 THIS DELETES THINGS AND CANNOT BE UNDONE. Three guards, in this order:
   1. Broker only. Not isStaff \u2014 an admin should not be able to empty the database.
   2. A preview endpoint that COUNTS what would go, per category, changing nothing.
      A destructive action with no preview is how the wrong category gets picked.
   3. The word DELETE, typed. Not a checkbox, not an "are you sure" \u2014 both of those
      get clicked through.

   \u26a0 WHAT IS DELIBERATELY NEVER TOUCHED, whatever is selected:
   agents, agent profiles and HR records, per-agent tab preferences and notification
   settings, articles, quiz wording, outside-tool links, site mode, award tiers,
   playbooks, the reel, testimonials, resource links, drip campaign definitions, and
   every other configuration key. Configuration is the work; records are the test. */

const RESET_GROUPS = {
  leads: {
    label: 'Leads and their alerts',
    prefixes: ['lead:', 'savedSearch:', 'ssTok:'],
    settings: ['settings:leadArchive'],
  },
  deals: {
    label: 'Deals, commissions and expenses',
    /* ⚠ 'receipt:' belongs here. The expense ROWS live in settings:expenses and the
       receipt FILES live under their own prefix, so clearing the expenses without
       this line would delete every row and leave the scanned receipts behind as
       orphaned blobs nothing points at and nothing can reach. */
    prefixes: ['agentDeals:', 'receipt:'],
    settings: ['settings:closedDeals', 'settings:closedYears', 'settings:expenses',
               'settings:dealSubmissions', 'settings:agentPlanHistory'],
  },
  sends: {
    label: 'Valuations, videos, open houses and sends',
    prefixes: ['cma:', 'cmafile:', 'cmaTok:', 'promo:', 'promoTok:',
               'tracker:', 'trackerTok:', 'openHouse:', 'ohTok:'],
    settings: ['settings:broadcasts'],
  },
  clients: {
    label: 'Client accounts and their sessions',
    prefixes: ['client:', 'clientSession:', 'clientReset:'],
    settings: [],
  },
  tasks: {
    label: 'Task lists and suggestions',
    prefixes: ['crmTasks:'],
    settings: ['settings:ideas'],
  },
};

/* \u26a0 A key must match a prefix EXACTLY at the start. 'cma:' must not sweep up
   'cmafile:' by accident \u2014 they are listed separately on purpose, and a startsWith
   on a shorter prefix elsewhere is how a delete quietly takes more than it named. */
async function resetScan(groups) {
  if (!supabase) return { rows: [], counts: {} };
  const { data, error } = await supabase.from(KV_TABLE).select('key');
  if (error) throw new Error(error.message);
  const all = (data || []).map(r => r.key).filter(Boolean);
  const rows = [];
  const counts = {};
  for (const g of groups) {
    const def = RESET_GROUPS[g];
    if (!def) continue;
    const hit = all.filter(k =>
      def.prefixes.some(p => k.startsWith(p)) || def.settings.includes(k));
    counts[g] = hit.length;
    rows.push(...hit);
  }
  return { rows: [...new Set(rows)], counts };
}

app.get('/api/reset/preview', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role !== 'broker') return res.status(403).json({ error: 'Broker only.' });
  try {
    const all = Object.keys(RESET_GROUPS);
    const { counts } = await resetScan(all);
    res.json({ ok: true,
      groups: all.map(g => ({ key: g, label: RESET_GROUPS[g].label, count: counts[g] || 0 })) });
  } catch (e) {
    console.error('[reset preview]', e.message);
    res.status(500).json({ error: 'Could not read the database.' });
  }
});

app.post('/api/reset', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role !== 'broker') return res.status(403).json({ error: 'Broker only.' });

  const b = req.body || {};
  if (String(b.confirm || '').trim() !== 'DELETE') {
    return res.status(400).json({ error: 'Type DELETE to confirm.' });
  }
  const groups = (Array.isArray(b.groups) ? b.groups : []).filter(g => RESET_GROUPS[g]);
  if (!groups.length) return res.status(400).json({ error: 'Nothing was selected.' });

  let rows;
  try { ({ rows } = await resetScan(groups)); }
  catch (e) {
    console.error('[reset]', e.message);
    return res.status(500).json({ error: 'Could not read the database.' });
  }
  if (!rows.length) {
    return res.json({ ok: true, deleted: 0, note: 'There was nothing there to remove.' });
  }

  /* \u26a0 Logged BEFORE the delete and in full. If this ever removes something it should
     not have, the log is the only record of what was there. */
  console.warn(`[reset] ${sess.name || sess.agentId} is deleting ${rows.length} record(s) `
    + `across [${groups.join(', ')}]`);

  let deleted = 0;
  for (let i = 0; i < rows.length; i += 100) {
    const chunk = rows.slice(i, i + 100);
    const { error } = await supabase.from(KV_TABLE).delete().in('key', chunk);
    if (error) {
      console.error(`[reset] FAILED after ${deleted}:`, error.message);
      return res.status(500).json({ error: `Removed ${deleted}, then hit an error. Run it again.` });
    }
    deleted += chunk.length;
  }
  console.warn(`[reset] done \u2014 ${deleted} record(s) removed by ${sess.name || sess.agentId}`);
  res.json({ ok: true, deleted });
});


/* ==================== THE MONTHLY MARKET LETTER (server 129) ====================
   The thing that runs whether or not anybody remembers. One email a month per person,
   about the town they told us they care about, built from live inventory at the moment
   of sending.

   \u26a0 Why this and not another lead source: the scoring engine, the lane engine and the
   click tracking are all built and all idle, because nothing goes out. A database
   nobody touches produces no signals, so the machinery that finds warm people has
   nothing to work with. Someone who opens three months running and then clicks two
   listings is a person about to move \u2014 and that is a daily viable lead the agent
   already knows, rather than a stranger who has to be bought.

   \u26a0 ACTIVE DATA ONLY. Everything here \u2014 counts, ranges, new this month, price cuts,
   days on market \u2014 comes from active listings, because that is the feed we have. It
   never says what anything SOLD for. Sellers want that number most; it needs the
   closed data we declined to buy, and inventing it is not an option.

   \u26a0 Nothing sends itself without being asked. There is no cron on this host, so this
   is a route the broker triggers. That is a feature, not a gap: a letter that goes out
   monthly on its own, to a list nobody re-read, is how a brokerage ends up apologising. */

const LETTER_LOG = 'settings:marketLetters';

/* ⚠ The bulk pull that /api/market-stats already does, lifted out so the letter and
   the stats page cannot drift apart — two functions computing "the market" from two
   different pulls is how a letter says 47 and the website says 45. */
async function marketRows() {
  const token = process.env.BRIDGE_SERVER_TOKEN, dataset = process.env.BRIDGE_DATASET;
  if (!token || !dataset) throw new Error('MLS not configured.');
  if (marketCache.rows && Date.now() - marketCache.rowsAt < 30 * 60 * 1000) return marketCache.rows;
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
  marketCache.rows = rows;
  marketCache.rowsAt = Date.now();
  return rows;
}

/* Which town a person actually cares about. The quiz asks directly, so that answer
   wins; otherwise fall back to a saved search or the listing they enquired about.
   ⚠ Returns '' rather than guessing. Somebody with no town gets no letter, which is
   better than a letter about the wrong place. */
function leadTown(l) {
  if (!l) return '';
  const q = l.quiz || {};
  if (Array.isArray(q.cities) && q.cities.length) return String(q.cities[0]);
  const c = l.criteria || {};
  if (Array.isArray(c.cities) && c.cities.length) return String(c.cities[0]);
  if (c.city) return String(c.city);
  if (l.city) return String(l.city);
  /* "412 Sandpiper Ln, Gulf Shores" — the town is what follows the last comma. */
  const label = String(l.listingLabel || '');
  if (label.includes(',')) {
    const tail = label.split(',').pop().trim().replace(/\s+[A-Z]{2}\s*\d{0,5}$/, '').trim();
    if (tail) return tail;
  }
  return '';
}



/* One town, from the rows already pulled for market-stats. */
function letterTownStats(rows, town) {
  const now = Date.now();
  const days = iso => iso ? (now - new Date(iso).getTime()) / 86400000 : 9999;
  const subset = rows.filter(r =>
    String(r.City || '').toLowerCase() === String(town).toLowerCase() && Number(r.ListPrice) > 0);
  if (!subset.length) return null;
  const prices = subset.map(r => Number(r.ListPrice)).sort((a, b) => a - b);
  const mid = prices[Math.floor(prices.length / 2)];
  const dom = subset.map(r => days(r.OnMarketDate || r.ModificationTimestamp))
    .filter(d => d < 3650).sort((a, b) => a - b);
  return {
    town,
    count: subset.length,
    low: prices[0],
    high: prices[prices.length - 1],
    median: mid,
    new30: subset.filter(r => days(r.OnMarketDate || r.ModificationTimestamp) <= 30).length,
    /* A price cut is the most honest signal in an active-only feed: it says the
       market disagreed with somebody. */
    cut: subset.filter(r => Number(r.OriginalListPrice) > Number(r.ListPrice)).length,
    medianDom: dom.length ? Math.round(dom[Math.floor(dom.length / 2)]) : 0,
  };
}

function money(n) { return '$' + Number(n || 0).toLocaleString('en-US', { maximumFractionDigits: 0 }); }

function letterText(s, first, sender, origin, unsub) {
  const month = new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
  const lines = [
    `Hi ${first},`,
    '',
    `Here is where ${s.town} stands as of ${month}.`,
    '',
    `\u00b7 ${s.count} home${s.count === 1 ? '' : 's'} on the market right now`,
    `\u00b7 From ${money(s.low)} to ${money(s.high)}, with the midpoint around ${money(s.median)}`,
    s.new30 ? `\u00b7 ${s.new30} came on in the last 30 days` : '',
    s.cut ? `\u00b7 ${s.cut} ${s.cut === 1 ? 'has' : 'have'} dropped their asking price` : '',
    s.medianDom ? `\u00b7 The typical one has been listed about ${s.medianDom} days` : '',
    '',
    'That is every active listing, counted this morning, not an estimate.',
    '',
    `See them: ${origin}/homes/${slugify(s.town)}`,
    '',
    'If you want to know what any particular one would mean for you, just reply.',
    '',
    '\u2014',
    sender.name || '',
    BROKERAGE_NAME,
    BROKERAGE_PHONE,
    BROKERAGE_ADDRESS,
    '',
    /* \u26a0 Said plainly, because a market letter that omits it implies sold prices are in
       there somewhere. They are not. */
    'These figures cover homes currently for sale. They do not include sale prices.',
    '',
    DISCLAIMER_EMAIL,
    '',
    `No longer want these? ${unsub}`,
  ];
  return lines.filter(l => l !== '').join('\n').replace(/\n\u2014\n/, '\n\n\u2014\n');
}

/* Who would get it, and what each of them would see. Changes nothing. */

/* ==================== THE WELCOME (server 131) ====================
   An introduction for people who are already in the database but have never heard
   from the site \u2014 imports from a previous system, an old spreadsheet, anybody added
   by hand. Everything built so far assumes a lead arrived through the site and knows
   what it is. Eighteen imported names do not.

   \u26a0 Sent once per person, ever. `welcomedAt` on the record is the guard, so an import
   run twice or a second press of the button cannot introduce somebody twice.

   \u26a0 This is a marketing send under CAN-SPAM: real postal address, honest subject,
   working unsubscribe. All three below, none of them optional. It goes only to people
   already in the database with an existing relationship \u2014 never a purchased list. */

app.post('/api/welcome/preview', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
  const mine = (data || []).map(x => x.value).filter(Boolean)
    .filter(l => isStaff(sess) || l.assignedAgentId === sess.agentId);
  const eligible = mine.filter(l => l.email && !l.unsubscribed && !l.welcomedAt);
  res.json({ ok: true,
    eligible: eligible.length,
    already: mine.filter(l => l.welcomedAt).length,
    noEmail: mine.filter(l => !l.email).length,
    unsubscribed: mine.filter(l => l.unsubscribed).length,
    sample: eligible.slice(0, 8).map(l => ({ name: l.name || '(no name)', email: l.email })) });
});

function welcomeText(lead, sender, origin, slug, unsub) {
  const first = String(lead.name || '').trim().split(/\s+/)[0] || 'there';
  const link = origin + (slug ? '/?agent=' + encodeURIComponent(slug) : '/');
  const town = (typeof leadTown === 'function') ? leadTown(lead) : '';
  return [
    `Hi ${first},`,
    '',
    `I have put our listings online in one place, and I wanted you to have the address`,
    `before anybody else does.`,
    '',
    link,
    '',
    `You can search every active listing on the coast${town ? ', including ' + town : ''} \u2014 no`,
    `sign-in needed to look around. If you make a free account it will remember your`,
    `favourites and email you when something new comes up that fits.`,
    '',
    `No obligation and nothing automated at you. If you would rather I just called when`,
    `something good turns up, reply and say so and I will.`,
    '',
    '\u2014',
    sender.name || '',
    BROKERAGE_NAME,
    BROKERAGE_PHONE,
    BROKERAGE_ADDRESS,
    '',
    DISCLAIMER_EMAIL,
    '',
    `Not interested in emails from us? ${unsub}`,
  ].join('\n');
}

/* ⚠ An HTML twin of welcomeText. The plain-text-only version arrived with the URL
   swallowing the first word of the next paragraph — `?agent=jimmythies\u2063\u2063You` — because a
   mail client left to guess where a bare URL ends will sometimes guess past the line
   break. An explicit <a href> removes the guess. `text` still goes with it as the
   fallback, so nothing is lost for anyone reading in plain text. */
function welcomeHtml(lead, sender, origin, slug, unsub) {
  const first = esc(String(lead.name || '').trim().split(/\s+/)[0] || 'there');
  const link = origin + (slug ? '/?agent=' + encodeURIComponent(slug) : '/');
  const town = (typeof leadTown === 'function') ? leadTown(lead) : '';
  return `<div style="font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#171F63;max-width:560px">
<p>Hi ${first},</p>
<p>I have put our listings online in one place, and I wanted you to have the address
before anybody else does.</p>
<p><a href="${esc(link)}" style="color:#171F63;font-weight:600">${esc(link)}</a></p>
<p>You can search every active listing on the coast${town ? ', including ' + esc(town) : ''}
&mdash; no sign-in needed to look around. If you make a free account it will remember
your favourites and email you when something new comes up that fits.</p>
<p>No obligation and nothing automated at you. If you would rather I just called when
something good turns up, reply and say so and I will.</p>
<p style="margin-top:26px;padding-top:16px;border-top:1px solid #E4E1D9">
${esc(sender.name || '')}<br>${esc(BROKERAGE_NAME)}<br>
${esc(BROKERAGE_PHONE)}<br>${esc(BROKERAGE_ADDRESS)}</p>
<p style="font-size:12.5px;color:#8C93AD;line-height:1.55">${esc(DISCLAIMER_EMAIL)}</p>
<p style="font-size:12.5px;color:#8C93AD">
Not interested in emails from us?
<a href="${esc(unsub)}" style="color:#8C93AD">Unsubscribe</a>.</p>
</div>`;
}

app.post('/api/welcome/send', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (!mailer) return res.status(503).json({ error: 'Email is not configured.' });

  /* \u26a0 Capped, like the market letter. This is very often the first real send from a
     brand-new domain, which is exactly when a large batch does the most damage. */
  const cap = Math.min(Math.max(parseInt((req.body || {}).cap, 10) || 25, 1), 200);
  const only = Array.isArray((req.body || {}).leadIds) ? (req.body || {}).leadIds : null;

  const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
  const origin = `${req.protocol}://${req.get('host')}`;
  const slug = slugify(sess.name || '');

  const queue = [];
  for (const row of (data || [])) {
    const l = row.value;
    if (!l || !l.email || l.unsubscribed || l.welcomedAt) continue;
    if (!isStaff(sess) && l.assignedAgentId !== sess.agentId) continue;
    if (only && !only.includes(l.id)) continue;
    queue.push({ key: row.key, lead: l });
    if (queue.length >= cap) break;
  }
  if (!queue.length) return res.json({ ok: true, sent: 0, note: 'Everybody has already had one.' });

  let sent = 0, failed = 0;
  for (let i = 0; i < queue.length; i += 8) {
    await Promise.all(queue.slice(i, i + 8).map(async ({ key, lead }) => {
      const unsub = `${origin}/unsub/${lead.id}.${unsubToken(lead.id)}`;
      try {
        await mailer.sendMail({
          to: lead.email,
          marketing: true,
          subject: `Every listing on the coast, in one place`,
          text: welcomeText(lead, sess, origin, slug, unsub),
          html: welcomeHtml(lead, sess, origin, slug, unsub),
        });
        sent++;
        lead.welcomedAt = new Date().toISOString();
        lead.events = Array.isArray(lead.events) ? lead.events : [];
        lead.events.push({ k: 'welcomed', at: lead.welcomedAt });
        await setSetting(key, lead);
      } catch (e) { failed++; console.error('[welcome]', lead.email, e.message); }
    }));
    if (i + 8 < queue.length) await new Promise(r => setTimeout(r, 900));
  }
  console.log(`[welcome] ${sent} sent, ${failed} failed, by ${sess.name || sess.agentId}`);
  res.json({ ok: true, sent, failed });
});

app.post('/api/market-letter/preview', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;

  let rows;
  try { rows = await marketRows(); }
  catch (e) {
    console.error('[letter] feed:', e.message);
    return res.status(502).json({ error: 'Could not reach the MLS feed.' });
  }

  const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
  const all = (data || []).map(x => x.value).filter(Boolean);
  const mine = all.filter(l => isStaff(sess) || l.assignedAgentId === sess.agentId);

  const byTown = {};
  let noTown = 0, noEmail = 0, unsubbed = 0;
  for (const l of mine) {
    if (!l.email) { noEmail++; continue; }
    if (l.unsubscribed) { unsubbed++; continue; }
    const town = leadTown(l);
    if (!town) { noTown++; continue; }
    (byTown[town] = byTown[town] || []).push(l);
  }

  const towns = Object.keys(byTown).sort().map(t => {
    const s = letterTownStats(rows, t);
    return { town: t, people: byTown[t].length, hasData: !!s,
      count: s ? s.count : 0, median: s ? s.median : 0 };
  });

  res.json({ ok: true, towns,
    skipped: { noTown, noEmail, unsubscribed: unsubbed },
    reachable: towns.filter(t => t.hasData).reduce((a, t) => a + t.people, 0) });
});

app.post('/api/market-letter/send', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (!mailer) return res.status(503).json({ error: 'Email is not configured.' });

  const b = req.body || {};
  const towns = (Array.isArray(b.towns) ? b.towns : []).map(t => String(t).slice(0, 60));
  if (!towns.length) return res.status(400).json({ error: 'Pick at least one town.' });
  /* \u26a0 A ceiling, on purpose. The brokerage's sending domain is new and has no
     reputation; the first months should be tens, not hundreds. Raise it deliberately
     rather than discovering the limit through a spam folder. */
  const cap = Math.min(Math.max(parseInt(b.cap, 10) || 30, 1), 400);

  let rows;
  try { rows = await marketRows(); }
  catch (e) { return res.status(502).json({ error: 'Could not reach the MLS feed.' }); }

  const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'lead:%');
  const origin = `${req.protocol}://${req.get('host')}`;
  const month = new Date().toISOString().slice(0, 7);

  const queue = [];
  for (const row of (data || [])) {
    const l = row.value;
    if (!l || !l.email || l.unsubscribed) continue;
    if (!isStaff(sess) && l.assignedAgentId !== sess.agentId) continue;
    const town = leadTown(l);
    if (!town || !towns.includes(town)) continue;
    /* \u26a0 Once per person per month, whatever else happens. Pressing the button twice
       must not send the same letter twice. */
    if (l.lastLetter === month) continue;
    const s = letterTownStats(rows, town);
    if (!s) continue;
    queue.push({ key: row.key, lead: l, stats: s });
    if (queue.length >= cap) break;
  }

  if (!queue.length) {
    return res.json({ ok: true, sent: 0, note: 'Nobody is due one this month.' });
  }

  let sent = 0, failed = 0;
  for (let i = 0; i < queue.length; i += 8) {
    const chunk = queue.slice(i, i + 8);
    await Promise.all(chunk.map(async ({ key, lead, stats }) => {
      const first = String(lead.name || '').trim().split(/\s+/)[0] || 'there';
      const unsub = `${origin}/unsub/${lead.id}.${unsubToken(lead.id)}`;
      try {
        await mailer.sendMail({
          to: lead.email,
          marketing: true,
          subject: `${stats.town} \u2014 ${stats.count} homes on the market right now`,
          text: letterText(stats, first, sess, origin, unsub),
        });
        sent++;
        lead.lastLetter = month;
        lead.events = Array.isArray(lead.events) ? lead.events : [];
        lead.events.push({ k: 'letter_sent', at: new Date().toISOString(), note: stats.town });
        await setSetting(key, lead);
      } catch (e) {
        failed++;
        console.error('[letter]', lead.email, e.message);
      }
    }));
    if (i + 8 < queue.length) await new Promise(r => setTimeout(r, 900));
  }

  try {
    const log = (await getSetting(LETTER_LOG)) || [];
    log.unshift({ at: new Date().toISOString(), by: sess.name || sess.agentId,
      month, towns, sent, failed });
    await setSetting(LETTER_LOG, log.slice(0, 60));
  } catch (e) {}

  console.log(`[letter] ${month}: ${sent} sent, ${failed} failed, by ${sess.name || sess.agentId}`);
  res.json({ ok: true, sent, failed });
});

app.get('/api/quick-links', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  const shared = await getSetting('settings:quickLinks');
  /* \u26a0 An agent's own links are keyed to their id and returned separately, so the
     client can show them apart and so nobody ever receives anybody else's.

     \u26a0 VIEW AS: this reads the REAL session, so a broker previewing an agent sees their
     own personal links rather than that agent's. Colors and layout deliberately follow
     the previewed agent; these deliberately do not. Personal means personal, including
     from the broker, and nobody asked for the ability to read everyone's bookmarks. */
  const mine = await getSetting('quickLinks:' + sess.agentId);
  res.json({ ok: true,
    links: Array.isArray(shared) ? shared : [],
    mine: Array.isArray(mine) ? mine : [] });
});

/* Their own. No role check \u2014 a personal link is only ever in front of the person who
   typed it, which is exactly why this one does not need the broker gate below. */
app.post('/api/quick-links/mine', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!Array.isArray((req.body || {}).links)) {
    return res.status(400).json({ error: 'Send a links array.' });
  }
  const clean = cleanLinks(req.body.links);
  await setSetting('quickLinks:' + sess.agentId, clean);
  console.log(`[links] ${sess.name || sess.agentId} saved ${clean.length} personal link(s)`);
  res.json({ ok: true, links: clean });
});

app.post('/api/quick-links', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role !== 'broker') {
    return res.status(403).json({ error: 'Only the broker can change these.' });
  }
  if (!Array.isArray((req.body || {}).links)) {
    return res.status(400).json({ error: 'Send a links array.' });
  }
  /* \u26a0 Same cleaner as the personal list. https only, and it must parse: a javascript:
     or data: URL on a row the whole brokerage clicks only has to work once. */
  const clean = cleanLinks(req.body.links);
  await setSetting('settings:quickLinks', clean);
  console.log(`[links] ${sess.name || sess.agentId} saved ${clean.length} outside tool link(s)`);
  res.json({ ok: true, links: clean });
});

app.post('/api/promo', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const b = req.body || {};
  const clean = (v, n) => String(v == null ? '' : v).slice(0, n).trim();

  const parsed = parseVideo(b.url);
  if (!parsed) {
    return res.status(400).json({
      error: 'Paste a YouTube or Vimeo link. Those are the two we can embed safely.' });
  }
  const title = clean(b.title, 120);
  if (!title) return res.status(400).json({ error: 'Give it a name so you can find it later.' });

  const id = 'vid_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  const rec = {
    id, title, note: clean(b.note, 400),
    kind: ['listing', 'marketing'].includes(b.kind) ? b.kind : 'marketing',
    address: clean(b.address, 140),
    ...parsed,
    /* \u26a0 CANONICAL, built from the parsed id \u2014 not what was pasted. People paste the
       provider's EMBED CODE, not a link: a whole <div><iframe src=...> blob. The
       regex finds the id inside it happily, but storing the blob and then putting it
       in an href produced bamacoast.com/<div style="padding:56.25%... and a 400 from
       Cloudflare. Never round-trip user input into a URL attribute. */
    sourceUrl: parsed.watchUrl,
    ownerId: sess.agentId, ownerName: sess.name || '',
    shared: b.shared !== false,          // brokerage-wide unless they say otherwise
    createdAt: new Date().toISOString(),
    sends: 0, opens: 0,
  };
  await setSetting('promo:' + id, rec);
  console.log(`[promo] ${sess.name || sess.agentId} added "${title}" (${parsed.provider})`);
  res.json({ ok: true, promo: rec });
});

app.get('/api/promo', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'promo:%');
    let rows = (data || []).map(x => x.value).filter(Boolean);
    /* Shared videos are the brokerage's; unshared ones belong to whoever added them. */
    if (!isStaff(sess)) rows = rows.filter(r => r.shared || r.ownerId === sess.agentId);
    rows.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, promos: rows.slice(0, 200) });
  } catch (e) {
    console.error('[promo list]', e.message);
    res.status(500).json({ error: 'Could not read those.' });
  }
});

app.delete('/api/promo/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const id = String(req.params.id || '').slice(0, 80);
  const rec = await getSetting('promo:' + id);
  if (!rec) return res.status(404).json({ error: 'Not there.' });
  if (!isStaff(sess) && rec.ownerId !== sess.agentId) {
    return res.status(403).json({ error: 'Not yours to remove.' });
  }
  try {
    const { error } = await supabase.from(KV_TABLE).delete().eq('key', 'promo:' + id);
    if (error) throw new Error(error.message);
  } catch (e) {
    console.error(`[promo] delete FAILED for ${id}:`, e.message);
    return res.status(500).json({ error: 'Could not remove that.' });
  }
  console.log(`[promo] ${sess.name || sess.agentId} removed "${rec.title}"`);
  res.json({ ok: true });
});

/* ---------- sending one to a person ---------- */
app.post('/api/promo/:id/send', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const rec = await getSetting('promo:' + String(req.params.id || '').slice(0, 80));
  if (!rec) return res.status(404).json({ error: 'That video is no longer there.' });

  const lead = await loadOwnLead(sess, (req.body || {}).leadId);
  if (!lead) return res.status(404).json({ error: 'Not your lead, or no longer there.' });

  /* \u26a0 The token is derived from the two ids rather than stored, so sending the same
     video to the same person twice gives the SAME link \u2014 which means the open count
     keeps adding up instead of starting again and quietly under-reporting. */
  const tok = promoToken(rec.id, lead.id);
  await setSetting('promoTok:' + tok, {
    promoId: rec.id, leadId: lead.id,
    agentId: sess.agentId, agentName: sess.name || '',
    sentAt: new Date().toISOString(),
  });
  rec.sends = (rec.sends || 0) + 1;
  await setSetting('promo:' + rec.id, rec);

  const origin = `${req.protocol}://${req.get('host')}`;
  console.log(`[promo] ${sess.name || sess.agentId} sent "${rec.title}" to ${lead.name || lead.id}`);
  res.json({ ok: true, url: `${origin}/v/${tok}`,
    lead: { id: lead.id, name: lead.name || '', email: lead.email || '' } });
});

/* ---------- what they open ---------- */
app.get('/v/:tok', async (req, res, next) => {
  const map = await getSetting('promoTok:' + String(req.params.tok || '').slice(0, 40));
  if (!map || !map.promoId) return next();
  const rec = await getSetting('promo:' + map.promoId);
  if (!rec) return next();

  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store');

  try {
    rec.opens = (rec.opens || 0) + 1;
    await setSetting('promo:' + map.promoId, rec);
    const lead = await getSetting('lead:' + map.leadId);
    if (lead) {
      lead.events = Array.isArray(lead.events) ? lead.events : [];
      lead.events.push({ k: 'video_play', at: new Date().toISOString(),
        note: String(rec.title).slice(0, 120) });
      lead.lastActivity = new Date().toISOString();
      const { score, band } = leadScore(lead);
      lead.score = score; lead.band = band.key;
      try { laneApply(lead, Date.now()); } catch (e) {}
      await setSetting('lead:' + map.leadId, lead);
      console.log(`[promo] ${lead.name || map.leadId} opened "${rec.title}"`);
    }
  } catch (e) { console.error('[promo] could not record the open:', e.message); }

  const esc = t => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const origin = `${req.protocol}://${req.get('host')}`;

  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(rec.title)}</title>
<style>
body{margin:0;background:#0E1433;color:#F5F3EC;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:860px;margin:0 auto;padding:34px 20px 56px}
.eb{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#E6C381;font-weight:700}
h1{font-family:Georgia,serif;font-size:29px;line-height:1.22;font-weight:400;margin:11px 0 6px}
.ad{color:rgba(245,243,236,.65);margin:0 0 22px;font-size:15px}
.fr{position:relative;padding-bottom:56.25%;height:0;border-radius:7px;overflow:hidden;
  background:#000;box-shadow:0 20px 50px rgba(0,0,0,.4)}
.fr iframe{position:absolute;inset:0;width:100%;height:100%;border:0}
.note{background:rgba(255,255,255,.06);border-left:3px solid #E6C381;border-radius:4px;
  padding:15px 17px;margin:24px 0 0;font-size:15px;line-height:1.7}
.ft{margin-top:32px;padding-top:22px;border-top:1px solid rgba(245,243,236,.16);
  font-size:14px;color:rgba(245,243,236,.7);line-height:1.75}
.ft strong{color:#F5F3EC}
.ft a{color:#E6C381}
</style></head><body><div class="w">
<div class="eb">${esc(BROKERAGE_NAME)}</div>
<h1>${esc(rec.title)}</h1>
${rec.address ? `<p class="ad">${esc(rec.address)}</p>` : '<div style="height:8px"></div>'}
<div class="fr"><iframe src="${esc(rec.embed)}" title="${esc(rec.title)}"
  allow="accelerometer; autoplay; clipboard-write; encrypted-media; picture-in-picture"
  referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe></div>
${rec.note ? `<div class="note">${esc(rec.note)}</div>` : ''}
<div class="ft">
  Sent by <strong>${esc(map.agentName || '')}</strong>, ${esc(BROKERAGE_NAME)}<br>
  ${esc(BROKERAGE_PHONE)}<br><br>
  <a href="${origin}/">See everything else on the market</a>
</div>
</div></body></html>`);
});

app.post('/api/cma', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;

  const b = req.body || {};
  const clean = (v, n) => String(v == null ? '' : v).slice(0, n).trim();
  const data = String(b.dataBase64 || '');
  if (!data) return res.status(400).json({ error: 'No file came through.' });

  /* \u26a0 Check the bytes, not the file name. A PDF starts %PDF-, which is JVBERi0 once
     base64-encoded. Renaming a .exe does not get past this. */
  if (!/^JVBERi0/.test(data.replace(/^data:[^,]*,/, ''))) {
    return res.status(400).json({ error: 'That does not look like a PDF.' });
  }
  const raw = data.replace(/^data:[^,]*,/, '');
  const bytes = Math.ceil(raw.length * 3 / 4);
  if (bytes > CMA_MAX_BYTES) {
    return res.status(413).json({ error: 'That PDF is too big \u2014 9MB is the ceiling.' });
  }

  /* Ownership decided here, on the real session, same rule as everywhere else. */
  const lead = await loadOwnLead(sess, b.leadId);
  if (!lead) return res.status(404).json({ error: 'Not your lead, or no longer there.' });

  const id = 'cma_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  const rec = {
    id,
    leadId: lead.id,
    leadName: lead.name || '',
    address: clean(b.address, 140) || 'Your home',
    note: clean(b.note, 400),
    filename: clean(b.filename, 90).replace(/[^A-Za-z0-9._ -]/g, '') || 'report.pdf',
    bytes,
    agentId: sess.agentId,
    agentName: sess.name || '',
    createdAt: new Date().toISOString(),
    opens: [],
  };
  /* \u26a0 The file lives under its OWN key prefix. Anything that lists 'cma:' to show the
     agent what has been sent would otherwise drag several megabytes of base64 back on
     every render. */
  await setSetting('cmafile:' + id, { b64: raw });
  await setSetting('cma:' + id, rec);
  await setSetting('cmaTok:' + cmaToken(id), { id });

  const origin = `${req.protocol}://${req.get('host')}`;
  console.log(`[cma] ${sess.name || sess.agentId} attached "${rec.address}" to ${lead.name || lead.id}`);
  res.json({ ok: true, cma: rec, url: `${origin}/cma/${cmaToken(id)}` });
});

/* ---------- what the seller opens ---------- */
app.get('/cma/:tok', async (req, res, next) => {
  const map = await getSetting('cmaTok:' + String(req.params.tok || '').slice(0, 40));
  if (!map || !map.id) return next();
  const rec = await getSetting('cma:' + map.id);
  if (!rec) return next();

  /* \u26a0 Never indexed. This is one seller's valuation of one house, reachable only by
     the token in their email \u2014 the same rule the article previews follow. */
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store');

  /* Record the open, then score it. Wrapped so a scoring failure cannot stop the
     seller seeing their report \u2014 but logged, because a silent failure here means the
     tracking quietly stops being true. */
  try {
    rec.opens = Array.isArray(rec.opens) ? rec.opens : [];
    rec.opens.push({ at: new Date().toISOString(),
      ua: String(req.get('user-agent') || '').slice(0, 120) });
    rec.opens = rec.opens.slice(-50);
    await setSetting('cma:' + map.id, rec);

    const lead = await getSetting('lead:' + rec.leadId);
    if (lead) {
      lead.events = Array.isArray(lead.events) ? lead.events : [];
      lead.events.push({ k: 'cma_open', at: new Date().toISOString(),
        note: rec.address.slice(0, 120) });
      lead.lastActivity = new Date().toISOString();
      const { score, band } = leadScore(lead);
      lead.score = score; lead.band = band.key;
      try { laneApply(lead, Date.now()); } catch (e) {}
      await setSetting('lead:' + rec.leadId, lead);
      console.log(`[cma] ${lead.name || rec.leadId} opened "${rec.address}" `
        + `(${rec.opens.length} time${rec.opens.length === 1 ? '' : 's'})`);
    }
  } catch (e) { console.error('[cma] could not record the open:', e.message); }

  const esc = t => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const origin = `${req.protocol}://${req.get('host')}`;
  const first = String(rec.leadName || '').trim().split(/\s+/)[0] || '';

  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(rec.address)}</title>
<style>
body{margin:0;background:#FBFAF7;color:#141A3C;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:620px;margin:0 auto;padding:44px 22px 60px}
.eb{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#C89B4E;font-weight:700}
h1{font-family:Georgia,serif;font-size:30px;line-height:1.2;font-weight:400;margin:12px 0 6px}
.sub{color:#5A6178;margin:0 0 26px;font-size:15px}
.note{background:#fff;border:1px solid rgba(20,26,60,.1);border-left:3px solid #C89B4E;
  border-radius:4px;padding:16px 18px;margin:0 0 26px;font-size:15px;line-height:1.7}
.btn{display:inline-block;background:#171F63;color:#fff;text-decoration:none;
  padding:15px 28px;border-radius:4px;font-weight:700;font-size:15px}
.btn:hover{background:#C89B4E;color:#241A08}
.meta{font-size:13px;color:#7A8199;margin-top:14px}
.ft{margin-top:38px;padding-top:22px;border-top:1px solid rgba(20,26,60,.12);
  font-size:13px;color:#5A6178;line-height:1.7}
.ft strong{color:#141A3C}
</style></head><body><div class="w">
<div class="eb">${esc(BROKERAGE_NAME)}</div>
<h1>${first ? esc(first) + ', here' : 'Here'} is what your home looks like on today's market</h1>
<p class="sub">${esc(rec.address)}</p>
${rec.note ? `<div class="note">${esc(rec.note)}</div>` : ''}
<a class="btn" href="${origin}/cma/${esc(req.params.tok)}/file">Open the report</a>
<div class="meta">PDF &middot; prepared ${esc(new Date(rec.createdAt).toLocaleDateString('en-US',
  { month: 'long', day: 'numeric', year: 'numeric' }))}</div>
<div class="ft">
  Prepared by <strong>${esc(rec.agentName)}</strong>, ${esc(BROKERAGE_NAME)}<br>
  ${esc(BROKERAGE_PHONE)}<br><br>
  Questions about any of it? Reply to the email this came in on, or call.
</div>
</div></body></html>`);
});

/* The file itself. Inline, so it opens in the browser rather than landing in
   downloads where nobody looks at it. */
app.get('/cma/:tok/file', async (req, res, next) => {
  const map = await getSetting('cmaTok:' + String(req.params.tok || '').slice(0, 40));
  if (!map || !map.id) return next();
  const rec = await getSetting('cma:' + map.id);
  const file = await getSetting('cmafile:' + map.id);
  if (!rec || !file || !file.b64) return next();
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store');
  res.type('application/pdf');
  res.set('Content-Disposition', `inline; filename="${rec.filename}"`);
  res.send(Buffer.from(file.b64, 'base64'));
});

/* ---------- what the agent sees ---------- */
app.get('/api/cma', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const leadId = String(req.query.leadId || '').slice(0, 80);
  try {
    const { data } = await supabase.from(KV_TABLE).select('key,value').ilike('key', 'cma:%');
    const origin = `${req.protocol}://${req.get('host')}`;
    let rows = (data || []).map(x => x.value).filter(Boolean);
    if (leadId) rows = rows.filter(r => r.leadId === leadId);
    /* Same scoping rule as the lead book: an agent sees what belongs to their people. */
    if (!isStaff(sess)) rows = rows.filter(r => r.agentId === sess.agentId);
    rows.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, cmas: rows.slice(0, 60).map(r => ({
      ...r, url: `${origin}/cma/${cmaToken(r.id)}`, openCount: (r.opens || []).length,
      lastOpen: (r.opens || []).length ? r.opens[r.opens.length - 1].at : null,
    })) });
  } catch (e) {
    console.error('[cma list]', e.message);
    res.status(500).json({ error: 'Could not read those.' });
  }
});

app.delete('/api/cma/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const id = String(req.params.id || '').slice(0, 80);
  const rec = await getSetting('cma:' + id);
  if (!rec) return res.status(404).json({ error: 'Not there.' });
  if (!isStaff(sess) && rec.agentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not yours to remove.' });
  }
  /* \u26a0 setSetting(key, null) is NOT a delete. It upserts a null value, and if the
     value column rejects null the upsert throws, setSetting swallows it and returns
     false, and the row survives untouched \u2014 while this route cheerfully reported
     success and the agent watched a removed valuation stay on screen.
     A real delete, with the error actually checked, the way /api/kv/:key does it. */
  const keys = ['cma:' + id, 'cmafile:' + id, 'cmaTok:' + cmaToken(id)];
  try {
    const { error } = await supabase.from(KV_TABLE).delete().in('key', keys);
    if (error) {
      console.error(`[cma] delete FAILED for ${id}:`, error.message);
      return res.status(500).json({ error: 'Could not remove that.' });
    }
  } catch (e) {
    console.error(`[cma] delete FAILED for ${id}:`, e.message);
    return res.status(500).json({ error: 'Could not remove that.' });
  }
  console.log(`[cma] ${sess.name || sess.agentId} removed "${rec.address}"`);
  res.json({ ok: true });
});


/* ==================== DELETING A LEAD IS NOT LOSING ONE (server 133) ====================
   ⚠ A lead was deleted by one click on an × and could not be got back. deleteLead()
   called storeDelete('lead:'+id) with no confirmation and no copy kept, and the row
   was gone from the database the moment the mouse came up. Real leads are the only
   irreplaceable thing in here — everything else can be re-entered from a bank
   statement or an MLS feed. A person who filled in a form once will not do it again.

   ⚠ `settings:leadArchive` already EXISTED — named in the admin key blocklist, named
   in the reset groups — and was written by absolutely nothing. Three references, zero
   writes. Same shape as drip.campaignId: it read as a built feature from every angle
   except the one that mattered. This is the half that was missing. */

const LEAD_ARCHIVE_MAX = 300;

app.post('/api/lead/:id/archive', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role === 'admin') {
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  const lead = await loadOwnLead(sess, req.params.id);
  if (!lead) return res.status(404).json({ error: 'Not your lead, or no longer there.' });

  const archive = (await getSetting('settings:leadArchive')) || [];
  const list = Array.isArray(archive) ? archive : [];
  /* The whole record, not a summary. A restore has to give back exactly what was
     there — score, events, quiz answers, drip state — or it is not a restore. */
  list.unshift({
    lead,
    deletedAt: new Date().toISOString(),
    deletedById: sess.agentId,
    deletedByName: sess.name || '',
  });
  /* ⚠ Capped, because this array is read whole. Oldest fall off the end. */
  if (list.length > LEAD_ARCHIVE_MAX) list.length = LEAD_ARCHIVE_MAX;

  /* ⚠ The copy is written BEFORE the original is removed. The other order loses the
     lead outright if the archive write fails — which, given setSetting used to return
     true on failed writes, is not hypothetical. mustSet answers 500 and stops. */
  if (!await mustSet(res, 'settings:leadArchive', list)) return;

  const { error } = await supabase.from(KV_TABLE).delete().eq('key', 'lead:' + lead.id);
  if (error) {
    console.error(`[lead archive] delete FAILED for ${lead.id}:`, error.message);
    return res.status(500).json({ error: 'Could not remove that. Nothing was lost.' });
  }
  console.log(`[lead archive] ${sess.name || sess.agentId} deleted "${lead.name || lead.id}" — recoverable`);
  res.json({ ok: true, id: lead.id, name: lead.name || '' });
});

app.get('/api/lead/archive', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role === 'admin') {
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  const archive = (await getSetting('settings:leadArchive')) || [];
  let rows = Array.isArray(archive) ? archive : [];
  /* Same scoping as the lead book: an agent sees what was theirs. */
  if (!isStaff(sess)) rows = rows.filter(r => r.lead && r.lead.assignedAgentId === sess.agentId);
  res.json({ ok: true, deleted: rows.slice(0, 100).map(r => ({
    id: r.lead ? r.lead.id : '',
    name: (r.lead && r.lead.name) || '',
    email: (r.lead && r.lead.email) || '',
    phone: (r.lead && r.lead.phone) || '',
    source: (r.lead && r.lead.source) || '',
    createdAt: (r.lead && r.lead.createdAt) || '',
    deletedAt: r.deletedAt, deletedByName: r.deletedByName || '',
  })) });
});

app.post('/api/lead/restore/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  if (sess.role === 'admin') {
    return res.status(403).json({ error: 'Leads are not available to admin accounts.' });
  }
  const id = String(req.params.id || '').slice(0, 80);
  const archive = (await getSetting('settings:leadArchive')) || [];
  const list = Array.isArray(archive) ? archive : [];
  const at = list.findIndex(r => r.lead && r.lead.id === id);
  if (at < 0) return res.status(404).json({ error: 'That is not in the deleted list.' });

  const entry = list[at];
  if (!isStaff(sess) && entry.lead.assignedAgentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not yours to restore.' });
  }
  /* ⚠ Never overwrite a live record. If something now occupies that key — a
     re-submission from the same person, most likely — the restore stops rather than
     silently replacing whatever is there with an older copy. */
  const existing = await getSetting('lead:' + id);
  if (existing) {
    return res.status(409).json({ error: 'A lead with that id is already back in the list.' });
  }

  /* Lead first, then the archive entry. If the second write fails the worst case is a
     duplicate row in the deleted list, which is visible and harmless. The other order
     can lose the record entirely. */
  if (!await mustSet(res, 'lead:' + id, entry.lead)) return;
  list.splice(at, 1);
  await setSetting('settings:leadArchive', list);

  console.log(`[lead archive] ${sess.name || sess.agentId} restored "${entry.lead.name || id}"`);
  res.json({ ok: true, lead: entry.lead });
});

/* ==================== RECEIPTS ON EXPENSES (server 132) ====================
   An expense with no receipt is a number the accountant has to take on faith. This
   attaches the paper — a PDF from a vendor, or far more often a photograph of a
   till receipt taken in a truck.

   ⚠ THE FILE DOES NOT GO ON THE EXPENSE ROW. Every expense in the brokerage lives in
   ONE array under settings:expenses, and that array is read whole on every render of
   the expenses screen, every print, and the year-end package. Putting base64 in it
   would mean a year of receipts is dragged down the wire to draw a table of numbers.
   Each file gets its own receipt:<id> key. The row carries an id, a filename and a
   byte count — enough to draw a link, and nothing more.

   ⚠ Photographs, not just PDFs. Agents scan receipts with a phone, so JPEG and PNG
   are first-class here. HEIC is refused BY NAME with an instruction, because an
   iPhone shooting in High Efficiency produces a file no browser will render and
   "that did not work" is a useless thing to tell somebody standing in a parking lot. */

const RECEIPT_MAX_BYTES = 9 * 1024 * 1024;   // ~12MB base64, under the 14mb json ceiling

/* ⚠ The bytes decide the type, not the file name. Renaming a .exe to .pdf gets you
   nowhere. Each entry is the base64 prefix a file of that type always starts with. */
const RECEIPT_TYPES = [
  { test: /^JVBERi0/,      mime: 'application/pdf', ext: 'pdf' },   // %PDF-
  { test: /^\/9j\//,       mime: 'image/jpeg',      ext: 'jpg' },   // FF D8 FF
  { test: /^iVBORw0KGgo/,  mime: 'image/png',       ext: 'png' },   // \x89PNG\r\n
];

function receiptSniff(raw) {
  return RECEIPT_TYPES.find(t => t.test.test(raw)) || null;
}

/* Who is allowed to touch this receipt. Ownership is not stored on the blob — it is
   read from the expense row that points at it, so it can never drift out of step with
   the ledger. Staff see everything, the way they do with deals and commissions. */
async function receiptOwner(id) {
  const list = await getSetting('settings:expenses');
  if (!Array.isArray(list)) return null;
  return list.find(e => e && e.receipt && e.receipt.id === id) || null;
}

app.post('/api/receipt', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;

  const b = req.body || {};
  const expenseId = String(b.expenseId || '').slice(0, 80);
  const data = String(b.dataBase64 || '');
  if (!expenseId) return res.status(400).json({ error: 'No expense was named.' });
  if (!data) return res.status(400).json({ error: 'No file came through.' });

  const raw = data.replace(/^data:[^,]*,/, '');
  const name = String(b.filename || '').slice(0, 90);

  const kind = receiptSniff(raw);
  if (!kind) {
    if (/\.heic$|\.heif$/i.test(name)) {
      return res.status(400).json({ error:
        'That is an iPhone HEIC photo, which browsers cannot display. On the phone: ' +
        'Settings \u2192 Camera \u2192 Formats \u2192 Most Compatible, then retake it. Or open the ' +
        'photo, tap Edit and Done, which saves a JPEG copy.' });
    }
    return res.status(400).json({ error:
      'That is not a PDF, a JPEG or a PNG. A photo of the receipt is fine.' });
  }

  const bytes = Math.ceil(raw.length * 3 / 4);
  if (bytes > RECEIPT_MAX_BYTES) {
    return res.status(413).json({ error: 'That file is too big \u2014 9MB is the ceiling.' });
  }

  const list = await getSetting('settings:expenses');
  if (!Array.isArray(list)) return res.status(404).json({ error: 'No expenses to attach to.' });
  const row = list.find(e => e && e.id === expenseId);
  if (!row) return res.status(404).json({ error: 'That expense is no longer there.' });
  if (!isStaff(sess) && row.agentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not your expense.' });
  }

  const id = 'rcp_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
  const filename = (name.replace(/[^A-Za-z0-9._ -]/g, '') || ('receipt.' + kind.ext));

  /* ⚠ The blob first. If the row is written first and the blob write then fails, the
     screen shows a receipt link pointing at nothing. This way the worst case is an
     unreferenced blob, which the reset sweep collects. */
  if (!await mustSet(res, 'receipt:' + id, { b64: raw, mime: kind.mime })) return;

  /* ⚠ Replacing an existing receipt removes the old blob. Otherwise re-photographing a
     blurry receipt leaves the blurry one in the database for ever. */
  const previous = row.receipt && row.receipt.id;

  row.receipt = { id, filename, bytes, mime: kind.mime,
                  uploadedAt: new Date().toISOString(),
                  byId: sess.agentId, byName: sess.name || '' };

  if (!await mustSet(res, 'settings:expenses', list)) {
    await delSetting('receipt:' + id);
    return;
  }
  if (previous && previous !== id) await delSetting('receipt:' + previous);

  console.log(`[receipt] ${sess.name || sess.agentId} attached ${filename} ` +
              `(${Math.round(bytes / 1024)}kb ${kind.mime}) to expense ${expenseId}`);
  res.json({ ok: true, receipt: row.receipt });
});

/* The file itself. Inline, so it opens rather than landing in downloads where nobody
   looks at it. Behind a session — unlike a CMA, which is deliberately reachable by an
   unauthenticated seller holding a token, a receipt is internal and has no such need. */
app.get('/api/receipt/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const id = String(req.params.id || '').slice(0, 80);

  const row = await receiptOwner(id);
  if (!row) return res.status(404).json({ error: 'Not there.' });
  if (!isStaff(sess) && row.agentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not yours.' });
  }
  const file = await getSetting('receipt:' + id);
  if (!file || !file.b64) return res.status(404).json({ error: 'The file is missing.' });

  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store');
  res.type(file.mime || 'application/octet-stream');
  res.set('Content-Disposition',
    `inline; filename="${(row.receipt.filename || 'receipt').replace(/["\\]/g, '')}"`);
  res.send(Buffer.from(file.b64, 'base64'));
});

app.delete('/api/receipt/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  const sess = await requireSession(req, res); if (!sess) return;
  const id = String(req.params.id || '').slice(0, 80);

  const list = await getSetting('settings:expenses');
  if (!Array.isArray(list)) return res.status(404).json({ error: 'Not there.' });
  const row = list.find(e => e && e.receipt && e.receipt.id === id);
  if (!row) return res.status(404).json({ error: 'Not there.' });
  if (!isStaff(sess) && row.agentId !== sess.agentId) {
    return res.status(403).json({ error: 'Not yours to remove.' });
  }

  const was = row.receipt.filename;
  delete row.receipt;
  if (!await mustSet(res, 'settings:expenses', list)) return;
  /* A real delete, checked. setSetting(key, null) upserts a null and leaves the row. */
  await delSetting('receipt:' + id);

  console.log(`[receipt] ${sess.name || sess.agentId} removed ${was} from expense ${row.id}`);
  res.json({ ok: true });
});

/* ==================== SHARING A LISTING (server 126) ====================
   \u26a0 The share buttons sent `/?listing=KEY` \u2014 the app shell with a query string. A
   social crawler does not run JavaScript, so Facebook fetched that, found the site's
   generic tags, and rendered a grey box reading "bamacoast.com". No address, no price,
   no photo. Sharing a listing produced a post nobody would click.

   Anything meant to be shared has to be a real page the server renders, with its own
   og:title, og:description and og:image. Same lesson as the article pages.

   \u26a0 noindex on purpose. Whether every listing in the feed should become an indexable
   page on this domain is an IDX question for Baldwin REALTORS, not one to answer by
   accident while fixing a share button. Crawlers read og: tags regardless of
   noindex, so sharing works either way. */
app.get('/listing/:key', async (req, res, next) => {
  const key = String(req.params.key || '').slice(0, 60);
  if (!key) return next();
  const origin = `${req.protocol}://${req.get('host')}`;
  const who = String(req.query.agent || '').slice(0, 60).replace(/[^a-z0-9-]/gi, '');

  let r;
  try {
    const esc = key.replace(/'/g, "''");
    const data = await bridgeGet(`OData/${BRIDGE_DATASET}/Property`, {
      $filter: `(ListingKey eq '${esc}' or ListingId eq '${esc}') and ${ACTIVE_ONLY}`,
      $top: 1,
    });
    r = (data.value || [])[0];
  } catch (e) {
    console.error('[listing share] feed:', e.message);
    return next();
  }
  /* Gone off market between the post and the click \u2014 which is normal, and better
     handled by sending them to the search than by a dead page. */
  if (!r) return res.redirect(302, origin + '/#listings');

  const e = t => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const price = r.ListPrice ? '$' + Number(r.ListPrice).toLocaleString() : 'Price on request';
  const addr  = [r.UnparsedAddress, r.City].filter(Boolean).join(', ');
  const bits  = [
    r.BedroomsTotal ? r.BedroomsTotal + ' bd' : '',
    r.BathroomsTotalInteger ? r.BathroomsTotalInteger + ' ba' : '',
    r.LivingArea ? Number(r.LivingArea).toLocaleString() + ' sq ft' : '',
  ].filter(Boolean).join(' \u00b7 ');
  const img = listingPhotoUrl(r, origin);
  const credit = listingCredit(r);
  const remarks = String(r.PublicRemarks || '').replace(/\s+/g, ' ').trim();
  const desc = [price, bits, remarks].filter(Boolean).join(' \u2014 ').slice(0, 300);
  const canon = `${origin}/listing/${encodeURIComponent(r.ListingKey || key)}`
    + (who ? `?agent=${encodeURIComponent(who)}` : '');
  const into = `${origin}/?listing=${encodeURIComponent(r.ListingKey || key)}`
    + (who ? `&agent=${encodeURIComponent(who)}` : '');

  console.log(`[listing share] ${addr} viewed${who ? ' via ' + who : ''}`);

  res.set('Cache-Control', 'public, max-age=600');
  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,follow">
<title>${e(addr)} \u2014 ${e(price)}</title>
<meta name="description" content="${e(desc)}">
<link rel="canonical" href="${e(canon)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="${e(BROKERAGE_NAME)}">
<meta property="og:title" content="${e(addr)} \u2014 ${e(price)}">
<meta property="og:description" content="${e(desc)}">
<meta property="og:url" content="${e(canon)}">
${img ? `<meta property="og:image" content="${e(img)}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="800">` : ''}
<meta name="twitter:card" content="${img ? 'summary_large_image' : 'summary'}">
<meta name="twitter:title" content="${e(addr)} \u2014 ${e(price)}">
<meta name="twitter:description" content="${e(desc)}">
${img ? `<meta name="twitter:image" content="${e(img)}">` : ''}
<style>
body{margin:0;background:#FBFAF7;color:#141A3C;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:720px;margin:0 auto;padding:30px 20px 60px}
.eb{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#C89B4E;font-weight:700}
.hero{width:100%;border-radius:7px;display:block;margin:14px 0 20px;background:#E9E7DF}
h1{font-family:Georgia,serif;font-size:31px;line-height:1.2;font-weight:400;margin:0 0 4px}
.pr{font-family:Georgia,serif;font-size:27px;color:#171F63;margin:0 0 6px}
.bits{font-size:15px;color:#5A6178;margin:0 0 20px}
.rm{font-size:15px;line-height:1.75;margin:0 0 24px}
.btn{display:inline-block;background:#171F63;color:#fff;text-decoration:none;
  padding:15px 28px;border-radius:4px;font-weight:700;font-size:15px}
.btn:hover{background:#C89B4E;color:#241A08}
.cr{font-size:12.5px;color:#7A8199;margin-top:22px;padding-top:16px;
  border-top:1px solid rgba(20,26,60,.12)}
.ft{font-size:13px;color:#5A6178;margin-top:8px;line-height:1.7}
</style></head><body><div class="w">
<div class="eb">${e(BROKERAGE_NAME)}</div>
${img ? `<img class="hero" src="${e(img)}" alt="${e(addr)}">` : ''}
<h1>${e(r.UnparsedAddress || 'Address on request')}</h1>
<div class="pr">${e(price)}</div>
<div class="bits">${e([r.City, r.StandardStatus].filter(Boolean).join(' \u00b7 '))}${
  bits ? ' \u00b7 ' + e(bits) : ''}</div>
${remarks ? `<p class="rm">${e(remarks.slice(0, 900))}</p>` : ''}
<a class="btn" href="${e(into)}">See the photos and more like it</a>
${credit ? `<div class="cr">${e(credit)}</div>` : ''}
<div class="ft">${e(BROKERAGE_NAME)} &middot; ${e(BROKERAGE_PHONE)}<br>
${e(DISCLAIMER_GENERAL).slice(0, 400)}</div>
</div></body></html>`);
});

app.get('/homes/:slug', async (req, res, next) => {
  const a = AREAS.find(x => x.slug === String(req.params.slug || '').toLowerCase());
  if (!a) return next();
  try {
    const origin = `${req.protocol}://${req.get('host')}`;
    const who = String(req.query.agent || '').slice(0, 60).replace(/[^a-z0-9-]/gi, '');
    const [stats, articles] = await Promise.all([
      areaStats(a.city),
      articlesPublic().catch(() => []),
    ]);
    res.type('html').send(
      areaSeoHtml(a, stats, origin, who, await siteIsPrivate(), articles));
  } catch (e) {
    console.error('[areas]', e.message);
    next();
  }
});

/* The index, so the twelve pages are reachable by a crawler and by a person. */
app.get('/homes', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const esc = t => String(t || '').replace(/</g, '&lt;');
  const priv = await siteIsPrivate();
  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Where to buy on the Alabama Gulf Coast | ${esc(BROKERAGE_NAME)}</title>
<meta name="description" content="Live listing counts and price ranges for every town we cover in Baldwin County and the Perdido Key corridor.">
<link rel="canonical" href="${origin}/homes">${priv ? '\n<meta name="robots" content="noindex,nofollow">' : ''}
<style>body{margin:0;background:#FBFAF7;color:#141A3C;font-family:'Public Sans',system-ui,sans-serif;line-height:1.7}
.w{max-width:760px;margin:0 auto;padding:38px 22px 70px}a{color:#141A3C;text-decoration:none}
h1{font-family:Georgia,serif;font-size:34px;font-weight:400;margin:0 0 8px}
.s{color:#5A6178;margin:0 0 26px}
.it{display:block;padding:18px 0;border-bottom:1px solid rgba(20,26,60,.1)}
.it .t{font-family:Georgia,serif;font-size:21px}
.it .b{font-size:14px;color:#5A6178;margin-top:4px;line-height:1.55}
.it:hover .t{color:#C89B4E}
.ft{margin-top:28px;font-size:13px;color:#7A8199}</style></head><body><div class="w">
<h1>Where to buy on this coast</h1>
<p class="s">Twelve towns, each with what is actually on the market there today.</p>
${AREAS.map(a => `<a class="it" href="${origin}/homes/${a.slug}">
  <div class="t">${esc(a.name)}</div>
  <div class="b">${esc(a.blurb.slice(0, 150))}${a.blurb.length > 150 ? '\u2026' : ''}</div></a>`).join('')}
<div class="ft">${esc(BROKERAGE_NAME)} &middot; ${esc(BROKERAGE_PHONE)}<br>
<a href="${origin}/">Search every active listing</a></div>
</div></body></html>`);
});

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

/* robots.txt moved below — it now depends on whether the site is private. */

/* Agent pages are the ones worth indexing individually — listings come and go
   and belong to the MLS, so they are deliberately left out. */
/* ---------- articles: SEO pages the newsletter also uses ----------
   The same writing does two jobs. A piece written for the monthly nurture email
   is also an indexable page at /insights/<slug>, so a stranger searching "gulf
   shores condo fees" lands on it with a lead form attached, and the newsletter
   sends traffic to your own domain rather than someone else's.

   Before this the whole site had two indexable page types: the homepage and
   agent bios. Every article added here is another way to be found. */
/* ⚠ Disclaimers are applied by the template, never by the author.
   Talking about insurance premiums, deductibles, loan terms or tax treatment
   edges toward advice that requires a licence we do not hold. A real estate
   licence is not an insurance licence, a mortgage licence, or a CPA.

   Articles carry a topic tag. Anything touching insurance, financing or tax gets
   the stronger wording on top of the general one. If an author forgets the tag,
   the keyword scan below catches it anyway — the failure mode is an extra
   disclaimer, not a missing one.

   ⚠ Have your attorney read this wording once. It is written to be sensible, not
   to be legal advice, and it is the kind of thing worth getting signed off. */
const DISCLAIMER_GENERAL =
  'This article is general information about the Alabama Gulf Coast market and is '
  + 'not advice about any specific property or situation. Market conditions change. '
  + 'Nothing here creates an agency relationship.';

/* \u26a0 The same disclaimer, minus the word "article". DISCLAIMER_GENERAL was written
   for blog posts and then pasted onto the welcome email and the market letter, neither
   of which is an article \u2014 so an introduction to the site arrived describing itself as
   one, and the broker read it and reasonably asked where the article was. A disclaimer
   that misnames the thing it is attached to undermines the disclaimer. */
const DISCLAIMER_EMAIL =
  'This email is general information about the Alabama Gulf Coast market and is '
  + 'not advice about any specific property or situation. Market conditions change. '
  + 'Nothing here creates an agency relationship.';

const DISCLAIMER_REGULATED =
  'We are licensed real estate agents. We are not insurance agents, mortgage '
  + 'brokers, lenders, attorneys or tax advisers, and nothing here is insurance, '
  + 'lending, legal or tax advice. Figures are general estimates that vary by '
  + 'property, carrier, lender and individual circumstances \u2014 they are not quotes '
  + 'and should not be relied on. Get quotes and advice from a licensed professional '
  + 'in the relevant field before making any decision.';

const REGULATED_WORDS = /insur|premium|deductible|mortgage|lender|loan|interest rate|financ|tax|escrow|apprais|flood zone|wind mitigation/i;

function articleRegulated(a) {
  if (a.topic === 'regulated') return true;
  if (a.topic === 'general') return false;
  return REGULATED_WORDS.test(String(a.title || '') + ' ' + String(a.body || ''));
}

function previewToken(slug) {
  return crypto.createHmac('sha256', HR_KEY || 'fallback')
    .update('preview:' + slug).digest('hex').slice(0, 16);
}

/* ---------- article artwork ----------
   Drawn here rather than photographed: no licence to worry about, it carries the
   brand, and it is a couple of kilobytes. Keyed by article id so an article
   without one simply renders without a header image. */
const ARTICLE_ART = {
  art_insurance: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="A house in high wind with a figure watching">
<rect width="720" height="260" fill="#F6EEDC"/>
<g stroke="#C89B4E" stroke-width="2.5" fill="none" opacity=".55" stroke-linecap="round">
<path d="M40 58 C130 36, 220 36, 300 54"/><path d="M20 88 C120 62, 240 62, 330 84"/>
<path d="M56 118 C140 98, 210 100, 268 112"/><path d="M30 158 C110 142, 176 144, 224 152"/></g>
<path d="M0 212 H720" stroke="#0E1433" stroke-width="2" opacity=".25"/>
<path d="M628 212 C622 178, 612 150, 578 130" stroke="#0E1433" stroke-width="6" fill="none" stroke-linecap="round"/>
<g stroke="#0E1433" stroke-width="5" fill="none" stroke-linecap="round" opacity=".9">
<path d="M578 130 C548 118, 520 118, 498 128"/><path d="M578 130 C552 132, 528 142, 512 158"/>
<path d="M578 130 C556 106, 532 96, 508 96"/></g>
<g transform="rotate(-5 430 172)">
<rect x="368" y="152" width="126" height="60" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M356 152 L431 106 L506 152 Z" fill="#C89B4E" stroke="#0E1433" stroke-width="3" stroke-linejoin="round"/>
<rect x="404" y="176" width="30" height="36" fill="#0E1433"/>
<rect x="448" y="168" width="26" height="20" fill="#4A7A9B" stroke="#0E1433" stroke-width="2.5"/></g>
<g fill="#C89B4E" stroke="#0E1433" stroke-width="2">
<rect x="300" y="100" width="26" height="14" rx="2" transform="rotate(-24 313 107)"/>
<rect x="252" y="128" width="22" height="12" rx="2" transform="rotate(-38 263 134)"/></g>
<g transform="translate(150 128)">
<circle cx="0" cy="0" r="15" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<ellipse cx="0" cy="6" rx="4" ry="5.5" fill="#0E1433"/>
<circle cx="-5.5" cy="-4" r="1.8" fill="#0E1433"/><circle cx="5.5" cy="-4" r="1.8" fill="#0E1433"/>
<path d="M-14 84 L-14 28 Q0 18 14 28 L14 84" fill="#0E1433"/>
<path d="M14 32 C26 24, 22 8, 8 10" stroke="#0E1433" stroke-width="6" fill="none" stroke-linecap="round"/>
<path d="M-14 32 C-28 40, -30 58, -22 68" stroke="#0E1433" stroke-width="6" fill="none" stroke-linecap="round"/></g></svg>`,

  art_condofees: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Two condo towers, one with many included layers and one with few">
<rect width="720" height="260" fill="#F6EEDC"/>
<path d="M0 224 H720" stroke="#0E1433" stroke-width="2" opacity=".25"/>
<rect x="150" y="52" width="150" height="172" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<g fill="#C89B4E" opacity=".92"><rect x="150" y="52" width="150" height="24"/>
<rect x="150" y="88" width="150" height="24"/><rect x="150" y="124" width="150" height="24"/>
<rect x="150" y="160" width="150" height="24"/><rect x="150" y="196" width="150" height="24"/></g>
<rect x="150" y="52" width="150" height="172" fill="none" stroke="#0E1433" stroke-width="3"/>
<rect x="420" y="52" width="150" height="172" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<rect x="420" y="196" width="150" height="24" fill="#C89B4E" opacity=".92"/>
<g stroke="#0E1433" stroke-width="2" opacity=".2" stroke-dasharray="7 7">
<path d="M420 76 H570"/><path d="M420 112 H570"/><path d="M420 148 H570"/><path d="M420 184 H570"/></g>
<rect x="420" y="52" width="150" height="172" fill="none" stroke="#0E1433" stroke-width="3"/>
<g transform="translate(360 132)"><circle r="30" fill="#0E1433"/>
<text y="9" text-anchor="middle" font-family="Georgia,serif" font-size="30" fill="#E8D2A0">?</text></g>
<text x="360" y="32" text-anchor="middle" font-family="sans-serif" font-size="12.5" letter-spacing="2.5" font-weight="700" fill="#C89B4E">WHAT THE FEE COVERS</text>
<text x="225" y="248" text-anchor="middle" font-family="sans-serif" font-size="14" font-weight="700" fill="#0E1433">$$$ / month</text>
<text x="495" y="248" text-anchor="middle" font-family="sans-serif" font-size="14" font-weight="700" fill="#0E1433">$ / month</text></svg>`,

  art_wherelive: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="A stylised coastline with four places marked">
<rect width="720" height="260" fill="#F6EEDC"/>
<path d="M0 186 C120 172, 240 204, 360 192 C480 180, 600 204, 720 190 L720 260 L0 260 Z" fill="#4A7A9B" opacity=".85"/>
<g stroke="#fff" stroke-width="2.5" fill="none" opacity=".45" stroke-linecap="round">
<path d="M60 220 c18 -8 34 8 52 0"/><path d="M250 236 c18 -8 34 8 52 0"/>
<path d="M470 220 c18 -8 34 8 52 0"/><path d="M620 238 c18 -8 34 8 52 0"/></g>
<path d="M0 186 C120 172, 240 204, 360 192 C480 180, 600 204, 720 190" stroke="#C89B4E" stroke-width="4" fill="none"/>
<g font-family="sans-serif" font-size="12" font-weight="700" fill="#0E1433" text-anchor="middle">
<g transform="translate(105 178)"><circle r="9" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M0 -9 L0 -46" stroke="#0E1433" stroke-width="2.5"/>
<rect x="-50" y="-70" width="100" height="24" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text y="-53">Fort Morgan</text></g>
<g transform="translate(285 196)"><circle r="12" fill="#C89B4E" stroke="#0E1433" stroke-width="3"/>
<path d="M0 -12 L0 -66" stroke="#0E1433" stroke-width="2.5"/>
<rect x="-52" y="-90" width="104" height="24" rx="3" fill="#C89B4E" stroke="#0E1433" stroke-width="2.5"/>
<text y="-73">Gulf Shores</text></g>
<g transform="translate(455 185)"><circle r="11" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M0 -11 L0 -46" stroke="#0E1433" stroke-width="2.5"/>
<rect x="-54" y="-70" width="108" height="24" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text y="-53">Orange Beach</text></g>
<g transform="translate(632 196)"><circle r="9" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M0 -9 L0 -40" stroke="#0E1433" stroke-width="2.5"/>
<rect x="-50" y="-64" width="100" height="24" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text y="-47">Perdido Key</text></g></g>
<text x="20" y="30" font-family="sans-serif" font-size="12" letter-spacing="2.5" font-weight="700" fill="#C89B4E">FORTY MILES, FIVE MARKETS</text></svg>`,

  art_firsttime: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Four numbered steps along a path toward a house">
<rect width="720" height="260" fill="#F6EEDC"/>
<path d="M40 190 C170 190, 170 96, 300 96 C430 96, 430 190, 560 190" stroke="#C89B4E" stroke-width="4" fill="none" stroke-dasharray="10 8"/>
<g font-family="sans-serif" text-anchor="middle">
<g transform="translate(40 190)"><circle r="26" fill="#0E1433"/><text y="7" font-size="20" fill="#E8D2A0" font-weight="700">1</text>
<text y="52" font-size="12.5" font-weight="700" fill="#0E1433">Talk to a lender</text></g>
<g transform="translate(300 96)"><circle r="26" fill="#0E1433"/><text y="7" font-size="20" fill="#E8D2A0" font-weight="700">2</text>
<text y="-38" font-size="12.5" font-weight="700" fill="#0E1433">Decide how you</text>
<text y="-22" font-size="12.5" font-weight="700" fill="#0E1433">will use it</text></g>
<g transform="translate(430 152)"><circle r="26" fill="#0E1433"/><text y="7" font-size="20" fill="#E8D2A0" font-weight="700">3</text>
<text y="52" font-size="12.5" font-weight="700" fill="#0E1433">See it in February</text></g>
<g transform="translate(560 190)"><circle r="26" fill="#C89B4E"/><text y="7" font-size="20" fill="#241A08" font-weight="700">4</text>
<text y="52" font-size="12.5" font-weight="700" fill="#0E1433">Inspection +</text>
<text y="68" font-size="12.5" font-weight="700" fill="#0E1433">insurance together</text></g></g>
<g transform="translate(646 150)">
<rect x="-26" y="0" width="52" height="40" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M-34 0 L0 -26 L34 0 Z" fill="#C89B4E" stroke="#0E1433" stroke-width="3" stroke-linejoin="round"/>
<rect x="-8" y="18" width="16" height="22" fill="#0E1433"/></g>
<text x="20" y="34" font-family="sans-serif" font-size="12" letter-spacing="2.5" font-weight="700" fill="#C89B4E">THE ORDER MATTERS</text></svg>`,

  art_sellprep: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Three things that move the sale price: photography, first-week pricing, and the obvious objection">
<rect width="720" height="260" fill="#F6EEDC"/>
<text x="360" y="34" text-anchor="middle" font-family="sans-serif" font-size="12" letter-spacing="2.5" font-weight="700" fill="#C89B4E">THREE THINGS MOVE THE NUMBER</text>
<g font-family="sans-serif" text-anchor="middle">
<g transform="translate(140 130)">
<rect x="-56" y="-40" width="112" height="80" rx="4" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<rect x="-20" y="-52" width="40" height="14" rx="3" fill="#0E1433"/>
<circle cy="0" r="22" fill="#C89B4E" stroke="#0E1433" stroke-width="3"/><circle cy="0" r="9" fill="#0E1433"/>
<text y="66" font-size="13" font-weight="700" fill="#0E1433">Photography</text>
<text y="84" font-size="11.5" fill="#7A8199">More than a kitchen</text></g>
<g transform="translate(360 130)">
<path d="M-46 -40 H26 L52 -14 L14 40 H-46 Z" fill="#C89B4E" stroke="#0E1433" stroke-width="3" stroke-linejoin="round"/>
<circle cx="26" cy="-18" r="6" fill="#0E1433"/>
<text x="-12" y="8" font-size="19" font-weight="700" fill="#241A08">WK 1</text>
<text y="66" font-size="13" font-weight="700" fill="#0E1433">The first week</text>
<text y="84" font-size="11.5" fill="#7A8199">Where the attention is</text></g>
<g transform="translate(580 130)">
<path d="M0 -44 L40 -28 V6 C40 30, 20 42, 0 48 C-20 42, -40 30, -40 6 V-28 Z" fill="#fff" stroke="#0E1433" stroke-width="3" stroke-linejoin="round"/>
<path d="M-16 2 L-4 16 L18 -12" stroke="#2E7D5B" stroke-width="6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
<text y="76" font-size="13" font-weight="700" fill="#0E1433">The obvious objection</text>
<text y="94" font-size="11.5" fill="#7A8199">Answered before it is asked</text></g></g></svg>`,

  art_eastern: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Mobile Bay with Fairhope, Daphne and Spanish Fort marked along the Eastern Shore">
<rect width="720" height="260" fill="#F6EEDC"/>
<path d="M0 60 C110 74, 150 130, 168 196 C176 226, 182 244, 190 260 L0 260 Z" fill="#4A7A9B" opacity=".85"/>
<path d="M0 60 C110 74, 150 130, 168 196 C176 226, 182 244, 190 260" stroke="#C89B4E" stroke-width="4" fill="none"/>
<g stroke="#fff" stroke-width="2.5" fill="none" opacity=".4" stroke-linecap="round">
<path d="M40 150 c16 -8 30 8 46 0"/><path d="M60 214 c16 -8 30 8 46 0"/></g>
<text x="52" y="118" font-family="sans-serif" font-size="12" font-weight="700" fill="#fff" opacity=".9">Mobile Bay</text>
<g font-family="sans-serif" font-size="12.5" font-weight="700" fill="#0E1433">
<g transform="translate(214 214)"><circle r="11" fill="#C89B4E" stroke="#0E1433" stroke-width="3"/>
<rect x="24" y="-14" width="150" height="28" rx="3" fill="#C89B4E" stroke="#0E1433" stroke-width="2.5"/>
<text x="99" y="5" text-anchor="middle">Fairhope &middot; walkable</text></g>
<g transform="translate(178 146)"><circle r="10" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<rect x="22" y="-14" width="150" height="28" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="97" y="5" text-anchor="middle">Daphne &middot; practical</text></g>
<g transform="translate(146 82)"><circle r="10" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<rect x="22" y="-14" width="176" height="28" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="110" y="5" text-anchor="middle">Spanish Fort &middot; the bridge</text></g></g>
<g stroke="#0E1433" stroke-width="3" fill="none" stroke-dasharray="8 7" opacity=".55">
<path d="M120 62 C90 50, 66 46, 40 48"/></g>
<text x="470" y="40" font-family="sans-serif" font-size="12" letter-spacing="2.5" font-weight="700" fill="#C89B4E">TWENTY MINUTES APART</text>
<text x="470" y="62" font-family="sans-serif" font-size="12" letter-spacing="2.5" font-weight="700" fill="#C89B4E">GENUINELY DIFFERENT</text></svg>`,

  art_moving: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="July crowded against February quiet, the seasonal split on the coast">
<rect width="720" height="260" fill="#F6EEDC"/>
<rect x="0" y="0" width="360" height="260" fill="#C89B4E" opacity=".22"/>
<path d="M360 0 V260" stroke="#0E1433" stroke-width="2" opacity=".3" stroke-dasharray="8 7"/>
<text x="180" y="40" text-anchor="middle" font-family="sans-serif" font-size="13" letter-spacing="2.5" font-weight="700" fill="#8A6A28">JULY</text>
<text x="540" y="40" text-anchor="middle" font-family="sans-serif" font-size="13" letter-spacing="2.5" font-weight="700" fill="#4A7A9B">FEBRUARY</text>
<path d="M0 206 H720" stroke="#0E1433" stroke-width="2" opacity=".25"/>
<g fill="#0E1433">
<g transform="translate(46 206)"><circle cy="-58" r="11"/><rect x="-11" y="-44" width="22" height="44" rx="4"/></g>
<g transform="translate(92 206)"><circle cy="-64" r="11"/><rect x="-11" y="-50" width="22" height="50" rx="4"/></g>
<g transform="translate(138 206)"><circle cy="-56" r="11"/><rect x="-11" y="-42" width="22" height="42" rx="4"/></g>
<g transform="translate(184 206)"><circle cy="-66" r="11"/><rect x="-11" y="-52" width="22" height="52" rx="4"/></g>
<g transform="translate(230 206)"><circle cy="-58" r="11"/><rect x="-11" y="-44" width="22" height="44" rx="4"/></g>
<g transform="translate(276 206)"><circle cy="-62" r="11"/><rect x="-11" y="-48" width="22" height="48" rx="4"/></g>
<g transform="translate(320 206)"><circle cy="-56" r="11"/><rect x="-11" y="-42" width="22" height="42" rx="4"/></g>
</g>
<g transform="translate(540 206)" fill="#0E1433" opacity=".85">
<circle cy="-62" r="11"/><rect x="-11" y="-48" width="22" height="48" rx="4"/></g>
<g stroke="#4A7A9B" stroke-width="3" fill="none" opacity=".5" stroke-linecap="round">
<path d="M420 172 c20 -9 38 9 58 0"/><path d="M600 182 c20 -9 38 9 58 0"/></g>
<text x="180" y="240" text-anchor="middle" font-family="sans-serif" font-size="12.5" font-weight="700" fill="#0E1433">Drive the route you would really drive</text>
<text x="540" y="240" text-anchor="middle" font-family="sans-serif" font-size="12.5" font-weight="700" fill="#0E1433">The beach to yourself</text></svg>`,

  art_rental: `<svg viewBox="0 0 720 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="A large gross arrow entering a house and smaller costs leaving">
<rect width="720" height="260" fill="#F6EEDC"/>
<path d="M0 224 H720" stroke="#0E1433" stroke-width="2" opacity=".25"/>
<rect x="20" y="96" width="170" height="40" fill="#C89B4E"/>
<path d="M190 80 L234 116 L190 152 Z" fill="#C89B4E"/>
<text x="105" y="123" text-anchor="middle" font-family="sans-serif" font-size="15" font-weight="700" fill="#241A08">GROSS</text>
<rect x="276" y="112" width="146" height="112" fill="#fff" stroke="#0E1433" stroke-width="3"/>
<path d="M262 112 L349 56 L436 112 Z" fill="#0E1433"/>
<rect x="318" y="168" width="34" height="56" fill="#0E1433"/>
<rect x="292" y="132" width="24" height="22" fill="#4A7A9B" stroke="#0E1433" stroke-width="2.5"/>
<rect x="382" y="132" width="24" height="22" fill="#4A7A9B" stroke="#0E1433" stroke-width="2.5"/>
<g font-family="sans-serif" font-size="11" font-weight="700" fill="#0E1433">
<g transform="translate(440 74)"><rect width="104" height="22" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="52" y="15" text-anchor="middle">Management</text><path d="M-16 11 H0" stroke="#0E1433" stroke-width="2.5"/></g>
<g transform="translate(458 110)"><rect width="86" height="22" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="43" y="15" text-anchor="middle">Cleaning</text><path d="M-34 11 H0" stroke="#0E1433" stroke-width="2.5"/></g>
<g transform="translate(440 146)"><rect width="104" height="22" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="52" y="15" text-anchor="middle">Fees + insurance</text><path d="M-16 11 H0" stroke="#0E1433" stroke-width="2.5"/></g>
<g transform="translate(458 182)"><rect width="86" height="22" rx="3" fill="#fff" stroke="#0E1433" stroke-width="2.5"/>
<text x="43" y="15" text-anchor="middle">Your weeks</text><path d="M-34 11 H0" stroke="#0E1433" stroke-width="2.5"/></g></g>
<g transform="translate(600 102)"><rect width="92" height="28" fill="#0E1433"/>
<path d="M92 7 L110 14 L92 21 Z" fill="#0E1433"/>
<text x="46" y="20" text-anchor="middle" font-family="sans-serif" font-size="13" font-weight="700" fill="#E8D2A0">NET</text></g></svg>`,
};

/* ⚠ NOT slugify(). That one strips characters and inserts nothing, which is right
   for agent pages (/jimmythies) and wrong for an article — it produced
   /insights/buyingyourfirstplaceonthegulfcoasttheordertodothingsin. Hyphens are
   also what search engines read as word boundaries. */
function articleSlugify(t) {
  return String(t || '').toLowerCase()
    .replace(/['\u2019]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80).replace(/-+$/, '');
}

function articleSlug(a) {
  return a.slug || articleSlugify(a.title || '');
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
  { id: 'art_firsttime', slug: 'buying-your-first-place-on-the-gulf-coast', topic: 'general',
    title: 'Buying your first place on the Gulf Coast: the order to do things in',
    teaser: 'Most people do these in the wrong order and lose a house because of it.',
    body: `The order matters more than the speed.

Talk to a lender before you look at anything. Not because you need to borrow immediately, but because knowing your actual number changes which stretch of coast you look at. People who tour first and get approved second almost always fall for something above their range.

Decide how you will use it before you decide where. Every weekend, two weeks a year, or renting it most of the season are three different purchases, and they point at different towns and different buildings.

See the area out of season if you can. February tells you more than July does. A place that feels quiet and lovely in the winter is a very different proposition from one that only works when everything is open.

Get the inspection and the insurance quotes running early, in parallel, not one after the other. On this coast the insurance number can change whether the deal makes sense, and finding that out in the last week is how contracts fall apart.` },

  { id: 'art_sellprep', slug: 'getting-a-gulf-coast-home-ready-to-sell', topic: 'general',
    title: 'What actually moves the number when you sell here',
    teaser: 'Three things account for most of the difference, and none of them is a renovation.',
    body: `Sellers tend to spend money on the wrong things.

Photography first. More people decide whether to visit from the photos than from anything else, and on the coast that means shooting when the light is right and the water shows. A bad photo set costs more than a kitchen.

The first week of pricing is the whole game. A listing priced correctly gets its most attention in the first seven to ten days. Priced high with a plan to reduce later, you spend that attention on nobody, and the reductions afterwards read as a problem rather than a bargain.

Deal with the obvious objection before anyone raises it. If the roof is fifteen years old, get the wind mitigation report and have it ready. If the building has an assessment coming, know the number. Buyers do not walk because of problems, they walk because of surprises.

Everything else is smaller than people think. Paint and decluttering earn their money. Full renovations before a sale rarely return what they cost.` },

  { id: 'art_rental', slug: 'gulf-coast-vacation-rental-numbers', topic: 'regulated',
    title: 'What a Gulf Coast rental actually brings in',
    teaser: 'The numbers people quote are gross. The ones that decide it are net.',
    body: `Rental projections shared between owners are almost always gross revenue, and gross revenue is not the number that matters.

Out of it comes management, usually a meaningful percentage for full service. Cleaning between stays. Condo fees, which on the coast frequently include the wind insurance and sometimes do not. Utilities. Maintenance, which runs higher on a rental than on a home because of the turnover. And the weeks you keep for yourself, which are not income but are the reason many people buy in the first place.

The rules matter as much as the numbers. Some buildings allow nightly rentals, some require a week minimum, some are owner-occupied only. That one rule can change the income by a factor of three, and it is set by the association rather than by you.

Seasonality is sharper here than people expect. Summer carries the year on much of this coast, and a building that performs beautifully in July can sit quiet for months.

If you are weighing a specific building, ask for actual owner statements rather than projections.` },

  { id: 'art_eastern', slug: 'fairhope-daphne-spanish-fort-eastern-shore', topic: 'general',
    title: 'Fairhope, Daphne or Spanish Fort: choosing on the Eastern Shore',
    teaser: 'Twenty minutes apart and genuinely different places to live.',
    body: `The Eastern Shore is a different decision from the beach, and people who start out looking at Gulf Shores often end up here.

Fairhope is the walkable one. A real downtown, independent shops, the pier, and a strong sense of place. It prices accordingly, and the closer to downtown the sharper that gets.

Daphne is larger and more practical. More housing at more price points, easy access to the causeway and Mobile, and less of a tourist rhythm to the year.

Spanish Fort sits closest to the bridge and is the shortest commute into Mobile. Newer construction, more subdivisions, and generally more house for the money than Fairhope.

The common thread is that this is year-round living rather than seasonal. Schools matter more here than rental rules do, and the market moves on a different calendar from the beach.

If you are moving from out of state and are not sure whether you want beach or bay, it is worth spending a day on each before deciding.` },

  { id: 'art_moving', slug: 'moving-to-baldwin-county-what-to-know', topic: 'general',
    title: 'Moving to Baldwin County: what nobody tells you first',
    teaser: 'The practical things that shape daily life here, beyond the house itself.',
    body: `The house is the easy part. These are the things that shape whether you enjoy living here.

Seasonality is real and it is sharp. Traffic on the beach roads between May and August is a different world from November. If you are choosing where to live, drive the route you would actually drive, in July.

Distances are longer than the map suggests. Baldwin County is one of the largest counties east of the Mississippi. Twenty miles can be twenty minutes or fifty depending on the season and the road.

Hurricane season runs June through November and it shapes everything from insurance to when people list their homes. It is not a reason to avoid the coast; it is a reason to understand what you are buying and how it is built.

Bay and beach are different climates in practice. The Eastern Shore is greener, shadier and cooler than the strip. People who assume the whole county feels like Gulf Shores are surprised by Fairhope.

Work out where you will actually spend your time before you choose a town. The people who are happiest here picked the daily life first and the house second.` },
];

/* ⚠ Draft by default. Deploying the server used to publish every seeded article
   the moment it went up, which put pages on the public internet that the broker
   had never read. Nothing is public now until somebody sets published:true on it
   deliberately. The seeds ship as drafts to be reviewed, not as live pages. */
async function articlesAll() {
  const saved = await getSetting(ARTICLES_KEY);
  const list = Array.isArray(saved) && saved.length ? saved : ARTICLE_DEFAULTS;
  return list.map(a => Object.assign({}, a, {
    slug: articleSlug(a),
    published: a.published === true,
  }));
}

async function articlesPublic() {
  return (await articlesAll()).filter(a => a.published);
}

/* Is the whole site meant to be discoverable yet? While it is being built the
   answer is no: search engines are told to stay out and the sitemap goes empty.
   ⚠ This hides the site from Google. It does NOT make it private — anyone with
   the URL can still reach it. Real privacy needs a login in front of everything,
   which would also block the lead capture the site exists for. */
async function siteIsPrivate() {
  const m = await getSetting('settings:siteMode');
  return m !== 'live';          // private until explicitly switched on
}

/* An article reached through an agent's newsletter belongs to that agent. The
   page carries ?agent=<slug> straight through to the call-to-action, so a lead
   created from it lands on them and not on the brokerage. Attribution here is
   the same rule as everywhere else: it does not expire and it is not silently
   handed back. */
function articleSeoHtml(a, origin, agentSlug, noindex, others) {
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
<link rel="canonical" href="${url}">${noindex ? '\n<meta name="robots" content="noindex,nofollow">' : ''}
<meta property="og:type" content="article">
<meta property="og:title" content="${esc(a.title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${url}">
<script type="application/ld+json">${JSON.stringify(ld)}</script>
<style>
body{margin:0;background:#FBFAF7;color:#141A3C;
  font-family:'Public Sans',system-ui,-apple-system,sans-serif;line-height:1.7}
.w{max-width:720px;margin:0 auto;padding:38px 22px 70px}
.art{margin:0 0 26px;border:1px solid rgba(20,26,60,.12);border-radius:5px;overflow:hidden;
  line-height:0}
.art svg{display:block;width:100%;height:auto}
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
.back{display:inline-block;font-size:12.5px;color:#7A8199;text-decoration:none;
  margin:0 0 20px;letter-spacing:.03em}
.back:hover{color:#C89B4E}
.more{margin-top:40px;padding-top:24px;border-top:1px solid rgba(20,26,60,.12)}
.more .eb{margin-bottom:12px}
.nx{display:block;padding:14px 0;border-bottom:1px solid rgba(20,26,60,.08);
  text-decoration:none}
.nx:last-child{border-bottom:none}
.nx .t{display:block;font-family:Georgia,serif;font-size:18px;color:#141A3C;line-height:1.3}
.nx .s{display:block;font-size:13.5px;color:#7A8199;margin-top:4px;line-height:1.5}
.nx:hover .t{color:#C89B4E}
.dis{margin-top:38px;padding:16px 18px;background:#fff;
  border:1px solid rgba(20,26,60,.12);border-radius:4px;
  font-size:12.5px;line-height:1.6;color:#5A6178}
.ft{margin-top:24px;padding-top:20px;border-top:1px solid rgba(20,26,60,.1);
  font-size:13px;color:#7A8199}
</style></head><body><div class="w">
<a class="back" href="${origin}/insights">&larr; All guides</a>
${ARTICLE_ART[a.id] ? `<div class="art">${ARTICLE_ART[a.id]}</div>` : ''}
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
${(others && others.length) ? `<div class="more">
  <div class="eb">Keep reading</div>
  ${others.slice(0, 3).map(o => `<a class="nx" href="${origin}/insights/${o.slug}${
    agentSlug ? '?agent=' + encodeURIComponent(agentSlug) : ''}">
    <span class="t">${esc(o.title)}</span>
    <span class="s">${esc(o.teaser || '')}</span></a>`).join('')}
</div>` : ''}
<div class="dis">${articleRegulated(a) ? esc(DISCLAIMER_REGULATED) + ' ' : ''}${esc(DISCLAIMER_GENERAL)}</div>
<div class="ft">${esc(BROKERAGE_NAME)} &middot; ${esc(BROKERAGE_PHONE)}<br>
${esc(BROKERAGE_ADDRESS)}<br>
<a href="${origin}/insights">More guides</a> &nbsp;&middot;&nbsp;
<a href="${origin}/">Search every active listing</a></div>
</div></body></html>`;
}

app.get('/insights', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const list = await articlesPublic();
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
<div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#C89B4E;
  font-weight:700;margin-bottom:8px">${esc(BROKERAGE_NAME)}</div>
<h1>Guides to buying and selling here</h1>
<p style="font-size:15px;color:#3D456B;margin:0 0 26px;max-width:620px">Straight answers
  about the Alabama Gulf Coast \u2014 what insurance really costs, what condo fees cover,
  and where to actually live. Written by people who work here.</p>
${list.length ? list.map(a => `<div class="it"><a href="${origin}/insights/${a.slug}">
  <h2>${esc(a.title)}</h2><p>${esc(a.teaser)}</p></a></div>`).join('\n')
  : '<p style="color:#7A8199">Nothing published yet.</p>'}
<div style="margin-top:34px;padding-top:20px;border-top:1px solid rgba(20,26,60,.1);
  font-size:13px;color:#7A8199">
  <a href="${origin}/" style="color:#C89B4E">Search every active listing on the coast</a>
  &nbsp;&middot;&nbsp; ${esc(BROKERAGE_PHONE)}</div>
</div></body></html>`);
});

app.get('/insights/:slug', async (req, res, next) => {
  try {
    // a draft is reachable only with the preview token, never by guessing the url
    const want = String(req.params.slug || '');
    const preview = req.query.preview === previewToken(want);
    const list = preview ? await articlesAll() : await articlesPublic();
    let a = list.find(x => x.slug === want);
    /* An article published before the slug fix has a hyphen-less URL in the wild.
       Match ignoring hyphens and send a permanent redirect to the real one, so
       nothing already emailed or indexed dies. */
    if (!a) {
      const bare = s => String(s).replace(/-/g, '');
      a = list.find(x => bare(x.slug) === bare(want));
      if (a && !preview) {
        return res.redirect(301, `/insights/${a.slug}`);
      }
    }
    if (!a) return next();
    const who = String(req.query.agent || '').slice(0, 60).replace(/[^a-z0-9-]/gi, '');
    // everything else that is live, so the reader always has somewhere to go next
    const others = (await articlesPublic()).filter(x => x.id !== a.id);
    res.type('html').send(articleSeoHtml(a, `${req.protocol}://${req.get('host')}`, who,
      (await siteIsPrivate()) || !a.published, others));
  } catch (e) { next(); }
});

/* The switch that decides whether the world can find this place. Broker only, and
   deliberately explicit — the site being reachable and the site being discoverable
   are different things, and confusing them costs months of search traffic. */
app.get('/api/site-mode', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  res.json({ ok: true, private: await siteIsPrivate() });
});

app.post('/api/site-mode', async (req, res) => {
  const sess = await requireSession(req, res); if (!sess) return;
  if (!isStaff(sess)) return res.status(403).json({ error: 'Broker only.' });
  const wantPrivate = (req.body || {}).private !== false;
  await setSetting('settings:siteMode', wantPrivate ? 'private' : 'live');
  console.log(`[site] switched to ${wantPrivate ? 'PRIVATE' : 'LIVE'} by ${sess.name || sess.agentId}`);
  res.json({ ok: true, private: wantPrivate });
});

app.get('/robots.txt', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  /* \u26a0 Never cache this. It is one line long, it changes the moment the broker presses
     a button, and a stale copy sitting in a CDN says "Disallow: /" to every crawler
     long after the site went live \u2014 which looks exactly like the switch not working. */
  res.set('Cache-Control', 'no-store, must-revalidate');
  if (await siteIsPrivate()) {
    return res.type('text/plain').send('User-agent: *\nDisallow: /\n');
  }
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${origin}/sitemap.xml\n`);
});

app.get('/sitemap.xml', async (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  res.set('Cache-Control', 'no-store, must-revalidate');
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
  if (await siteIsPrivate()) {
    // nothing to advertise while the site is still being built
    return res.type('application/xml').send(
      '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>\n');
  }
  try {
    urls.push({ loc: origin + '/insights', pri: '0.7' });
    (await articlesPublic()).forEach(a => {
      urls.push({ loc: origin + '/insights/' + a.slug, pri: '0.7' });
    });
  } catch (e) { console.warn('[sitemap] articles failed:', e.message); }
  /* Area pages carry the highest commercial intent of anything here, so they go in
     above the guides. */
  urls.push({ loc: origin + '/homes', pri: '0.9' });
  AREAS.forEach(a => { urls.push({ loc: origin + '/homes/' + a.slug, pri: '0.9' }); });
  const today = new Date().toISOString().slice(0, 10);
  res.type('application/xml').send(
`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${u.loc}</loc><lastmod>${today}</lastmod><priority>${u.pri}</priority></url>`).join('\n')}
</urlset>
`);
});

// ---------- static site ----------
/* ⚠ Served with no cache headers, index.html could sit in an intermediate cache for
   ten or twenty minutes after a deploy — long enough to look like a fix did not work,
   and the single biggest time sink in these sessions. A hard reload does not help,
   because the stale copy is upstream of the browser.

   index.html must be revalidated every time (it is the whole app, and it changes on
   every deploy). Everything else is fingerprinted or rarely changes, so it can be
   cached properly. */
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  lastModified: true,
  setHeaders(res, filePath) {
    if (/index\.html$/i.test(filePath)) {
      res.set('Cache-Control', 'no-cache, must-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
    } else if (/\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf)$/i.test(filePath)) {
      res.set('Cache-Control', 'public, max-age=604800');   // a week for images and fonts
    } else {
      res.set('Cache-Control', 'public, max-age=3600');
    }
  },
}));

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
