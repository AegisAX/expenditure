/*
 * [CSRF Auto-Recovery] — v2 진단 모드
 *
 * 기존엔 403 + code:'CSRF_INVALID' 응답이 오면 SweetAlert 안내 후 자동 reload 했지만,
 * 어떤 환경에서 mismatch 가 끊임없이 발생할 경우 reload → 또 mismatch → reload 의
 * 무한 루프가 생겨 사용자가 페이지 안에서 아무것도 못 하게 된다.
 *
 * 진단을 위해 현재 버전은:
 *   - 자동 reload 를 끔
 *   - 콘솔에 [CSRF Guard] 경고만 출력 (다중 알림 방지 1회 가드)
 *   - 응답은 그대로 통과 → 호출자(fetch then) 가 자체 에러 처리
 *
 * 원인 파악 후 다시 자동 reload 를 복구할 예정.
 */
(function() {
    'use strict';

    if (window.__csrfGuardInstalled) return;
    window.__csrfGuardInstalled = true;

    const originalFetch = window.fetch.bind(window);
    let warned = false;

    window.fetch = async function(...args) {
        const response = await originalFetch(...args);
        if (response.status !== 403) return response;

        try {
            const cloned = response.clone();
            const ct = (cloned.headers.get('content-type') || '').toLowerCase();
            if (!ct.includes('application/json')) return response;

            const data = await cloned.json();
            if (data && data.code === 'CSRF_INVALID' && !warned) {
                warned = true;
                console.warn('[CSRF Guard] CSRF 토큰 검증 실패. (자동 reload 비활성 — 무한 루프 방지 모드)\n' +
                             '서버 로그의 [CSRF Error] 라인과, DevTools > Application > Cookies 의 connect.sid 존재 여부를 확인하세요.');
            }
        } catch (_) { /* JSON 아니면 무시 */ }

        return response;
    };
})();
