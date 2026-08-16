// Minimal service worker — mainly here so the site qualifies as an
// installable app on phones ("Add to Home Screen"). Caches the shell
// page for a slightly faster repeat visit; does not aggressively cache
// listings or API responses, since that data should always be fresh.

const CACHE_NAME = 'avani-co-shell-v1';
const SHELL_FILES = ['/', '/index.html', '/assets/logo.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Never intercept API calls — those must always hit the network live.
  if (event.request.url.includes('/api/')) return;

  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
