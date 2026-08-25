import {
  createSyncEventHandler,
  handleClientMessage,
} from "./services/offline/swSyncBridge";

interface ExtendableEventLike {
  waitUntil: (promise: Promise<unknown>) => void;
}

interface SyncEventLike extends ExtendableEventLike {
  tag: string;
}

interface MessageEventLike extends ExtendableEventLike {
  data?: unknown;
  source: ClientMessageSource | null;
}

interface FetchEventLike extends ExtendableEventLike {
  request: Request;
  respondWith(response: Promise<Response> | Response): void;
}

interface ClientMessageSource {
  postMessage: (message: unknown) => void;
}

interface ClientListLike {
  claim: () => Promise<void>;
  matchAll: (options?: { type?: string; includeUncontrolled?: boolean }) => Promise<
    ClientMessageSource[]
  >;
}

interface ServiceWorkerScopeLike {
  location: { origin: string };
  registration: Parameters<typeof handleClientMessage>[1];
  clients: ClientListLike;
  skipWaiting: () => Promise<void>;
  addEventListener(type: "install", listener: (event: ExtendableEventLike) => void): void;
  addEventListener(type: "activate", listener: (event: ExtendableEventLike) => void): void;
  addEventListener(type: "sync", listener: (event: SyncEventLike) => void): void;
  addEventListener(type: "message", listener: (event: MessageEventLike) => void): void;
  addEventListener(type: "fetch", listener: (event: FetchEventLike) => void): void;
}

const swSelf = self as unknown as ServiceWorkerScopeLike;

const SHELL_CACHE = "spoovault-shell-v1";
const ASSET_CACHE = "spoovault-assets-v1";
const IPFS_CACHE = "spoovault-ipfs-v1";

const KNOWN_CACHES = new Set([SHELL_CACHE, ASSET_CACHE, IPFS_CACHE]);

swSelf.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(["/", "/index.html"]))
      .then(() => swSelf.skipWaiting())
  );
});

swSelf.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => !KNOWN_CACHES.has(key))
            .map((key) => caches.delete(key))
        )
      )
      .then(() => swSelf.clients.claim())
  );
});

async function networkFirst(request: Request, cacheName: string): Promise<Response> {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }
    throw error;
  }
}

async function staleWhileRevalidate(request: Request, cacheName: string): Promise<Response> {
  const cache = await caches.open(cacheName);
  const cachedResponse = await cache.match(request);
  const fetchPromise = fetch(request).then((networkResponse) => {
    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  }).catch(() => {
    return new Response('', { status: 504, statusText: 'Gateway Timeout' });
  });
  return cachedResponse || fetchPromise;
}

async function cacheFirst(request: Request, cacheName: string): Promise<Response> {
  const cachedResponse = await caches.match(request);
  if (cachedResponse) {
    return cachedResponse;
  }
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    throw error;
  }
}

swSelf.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  if (event.request.mode === "navigate") {
    event.respondWith(networkFirst(event.request, SHELL_CACHE));
    return;
  }

  if (
    url.origin === swSelf.location.origin &&
    ["script", "style", "image", "font", "worker"].includes(event.request.destination)
  ) {
    event.respondWith(staleWhileRevalidate(event.request, ASSET_CACHE));
    return;
  }

  if (/pinata\.cloud$/.test(url.hostname) && url.pathname.includes("/ipfs/")) {
    event.respondWith(cacheFirst(event.request, IPFS_CACHE));
    return;
  }
});

swSelf.addEventListener(
  "sync",
  createSyncEventHandler(swSelf.clients, {
    onReplayBroadcast: (clientCount) => {
      if (clientCount === 0) {
      }
    },
  })
);

swSelf.addEventListener("message", (event) => {
  const source = event.source;
  event.waitUntil(
    handleClientMessage(event.data, swSelf.registration, (reply) => {
      source?.postMessage(reply);
    })
  );
});
