// Minimal service worker — mainly here so the site qualifies as an installable app
// on phones ("Add to Home Screen").
//
// ⚠ THE APP SHELL IS NOT PRECACHED ANY MORE, and that is the whole point of this
// version. The previous one listed '/' and '/index.html' in SHELL_FILES and cached
// them on install. Its fetch handler was network-first, so in theory that copy was
// only ever a fallback — but it meant a complete, months-old copy of the entire
// application was sitting in cache storage on every device, reachable the moment any
// fetch hiccupped, and surviving hard refreshes and cache clears because a service
// worker sits upstream of both.
//
// index.html is 1.3MB and changes several times a day. It is the last thing that
// should be in an offline cache. Nothing is precached now except the logo.
//
// ⚠ Bumping CACHE_NAME is what retires the old cache: activate deletes every cache
// whose name is not this one. Bump it whenever this file changes.

const CACHE_NAME = 'avani-co-shell-v2';
const SHELL_FILES = ['/assets/logo.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) =>
        Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only ever touch same-origin GETs. Anything else is none of our business.
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (e) { return; }
  if (url.origin !== self.location.origin) return;

  // API calls must always be live.
  if (url.pathname.startsWith('/api/')) return;

  // ⚠ Page loads are handed straight to the network with the HTTP cache bypassed.
  // Not network-first with a cache fallback — network ONLY. A stale page is worse
  // than an error page here: an error you retry, a stale page you spend an hour
  // deploying against and never notice.
  const isPage = req.mode === 'navigate' ||
                 (req.headers.get('accept') || '').includes('text/html');
  if (isPage) {
    event.respondWith(fetch(req, { cache: 'no-store' }).catch(() => fetch(req)));
    return;
  }

  // Everything else: try the network, fall back to whatever was cached. Images and
  // fonts are safe to serve stale; markup is not.
  event.respondWith(fetch(req).catch(() => caches.match(req)));
});
