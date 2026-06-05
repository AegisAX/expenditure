/*
 * [PWA Bootstrap]
 *
 * Service Worker 가 옛 캐시(이전 라이브러리: Quill, CKEditor classic 등)를
 * 계속 응답으로 주는 사고를 막기 위한 첫-진입 정리 스크립트.
 *
 * 동작 (한 페이지당 최대 1회):
 *   - localStorage 의 sw 버전이 SW_VERSION 과 같으면 — 이미 정리됨, no-op
 *   - 다르면(또는 없음):
 *       1) 등록된 모든 service worker unregister
 *       2) caches.keys() 의 모든 캐시 삭제
 *       3) 버전 기록 — 자동 reload 는 하지 않는다 (CSRF·로그인 흐름이 깨질 수 있음).
 *          다음 자연스러운 페이지 이동/새로고침에서 새 자원이 자동 적용된다.
 *
 * v2-no-auto-reload : reload 동작을 제거한 버전. 이전 버전(v2)이 무한 reload·세션 손실을
 *                     유발한 사례를 차단.
 */
(function() {
    'use strict';

    const SW_VERSION = 'v2-no-auto-reload';
    const KEY        = 'kumoh_sw_version';

    if (!('serviceWorker' in navigator)) return;

    let lastSeen = null;
    try { lastSeen = localStorage.getItem(KEY); } catch (_) {}

    if (lastSeen === SW_VERSION) return;   // 이미 한 번 정리 완료

    // 1회만 실행 — localStorage 에 먼저 기록해 두고 시작.
    try { localStorage.setItem(KEY, SW_VERSION); } catch (_) {}

    const unregisterAll = navigator.serviceWorker.getRegistrations().then(regs =>
        Promise.all(regs.map(r => r.unregister().catch(() => false)))
    );
    const clearAllCaches = (window.caches
        ? caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k).catch(() => false))))
        : Promise.resolve());

    Promise.all([unregisterAll, clearAllCaches])
        .then(() => console.warn('[PWA Bootstrap] 옛 service worker / 캐시 정리 완료.'))
        .catch(err => console.warn('[PWA Bootstrap] 정리 실패:', err));
})();
