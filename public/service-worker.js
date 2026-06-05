/*
 * [Service Worker — No-Op]
 *
 * PWA 기능은 일시 비활성화. 이 sw 는 어떤 fetch 도 가로채지 않고
 * 어떤 캐시도 사용하지 않는다. 활성된 sw 는 그대로 두고 새로운 자살·navigate
 * 동작도 하지 않아 무한 reload 사이클을 끊는다.
 *
 * 옛 sw 정리는 /js/sw-bootstrap.js 가 페이지 로드 시 한 번 수행한다.
 *
 * 추후 PWA 재도입 시 이 파일을 새로 작성한다.
 */
self.addEventListener('install', () => {
    self.skipWaiting();
});
self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});
// fetch 이벤트 리스너를 등록하지 않음 — 모든 요청이 sw 를 우회해 직접 네트워크로.
