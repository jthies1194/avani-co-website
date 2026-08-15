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

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    database: !!supabase,
    mlsConfigured: !!(process.env.BRIDGE_SERVER_TOKEN && process.env.BRIDGE_DATASET),
  });
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
