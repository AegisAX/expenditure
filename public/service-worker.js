const CACHE_NAME = 'kumoh-pwa-v1';

// 캐싱할 정적 파일들 (CSS, JS, 이미지 등 변경이 적은 것들)
const STATIC_ASSETS = [
    '/manifest.json',
    '/icons/icon-192x192.png',
    '/icons/icon-512x512.png'
];

// 1. 설치 (Install)
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(STATIC_ASSETS);
        })
    );
    self.skipWaiting(); // 즉시 활성화
});

// 2. 활성화 (Activate) - 구버전 캐시 정리
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
            );
        })
    );
    self.clients.claim();
});

// 3. 요청 가로채기 (Fetch) - [중요] 네트워크 우선 전략
// 데이터 무결성과 CSRF 토큰 문제를 방지하기 위해 HTML과 API는 캐시하지 않고 항상 네트워크를 통하게 합니다.
self.addEventListener('fetch', (event) => {
    // API 요청이나 HTML 페이지는 무조건 네트워크로 요청 (캐시 안 함)
    if (event.request.mode === 'navigate' || event.request.url.includes('/api/')) {
        event.respondWith(fetch(event.request));
        return;
    }

    // 정적 자원(이미지, CSS 등)은 캐시가 있으면 쓰고, 없으면 네트워크로
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            return cachedResponse || fetch(event.request);
        })
    );
});