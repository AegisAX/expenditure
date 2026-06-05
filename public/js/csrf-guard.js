/*
 * [CSRF Auto-Recovery]
 *
 * 가끔 사용자가 로그인 페이지나 작성 폼을 오래 띄워둔 채로 요청을 보내면
 * 서버 세션·CSRF 토큰이 만료되어 다음과 같은 응답이 돌아온다.
 *   HTTP 403 { status:'Error', code:'CSRF_INVALID', msg:'보안 토큰이 만료...' }
 *
 * 기존에는 SweetAlert 에러창의 OK 를 눌러도 아무 일이 일어나지 않아
 * 사용자가 직접 새로고침해야 했다. 이 스크립트는 그 동작을 자동화한다.
 *
 *  - window.fetch 를 래핑해 모든 응답을 감시
 *  - status===403 이고 본문에 code==='CSRF_INVALID' 면 SweetAlert 안내 후
 *    OK 클릭 시 페이지 자동 새로고침
 *  - SweetAlert 미로드 환경에서는 alert() + reload 로 fallback
 *
 * 본 핸들러는 한 페이지당 한 번만 트리거되도록 in-flight 락을 둔다
 * (여러 fetch 가 동시에 실패해도 알림이 1번만 뜨도록).
 */
(function() {
    'use strict';

    if (window.__csrfGuardInstalled) return;
    window.__csrfGuardInstalled = true;

    const originalFetch = window.fetch.bind(window);
    let prompting = false;

    function notifyAndReload(msg) {
        if (prompting) return;
        prompting = true;

        const safeMsg = msg || '보안 토큰이 만료되었습니다.<br>페이지를 새로고침합니다.';

        if (typeof window.Swal !== 'undefined') {
            window.Swal.fire({
                icon: 'warning',
                title: '세션 갱신 필요',
                html: safeMsg,
                confirmButtonText: '새로고침',
                allowOutsideClick: false,
                allowEscapeKey: false
            }).then(() => window.location.reload());
        } else {
            // SweetAlert2 가 아직 로드되지 않은 매우 이른 케이스
            const plain = safeMsg.replace(/<br\s*\/?\s*>/gi, '\n');
            window.alert(plain);
            window.location.reload();
        }
    }

    window.fetch = async function(...args) {
        const response = await originalFetch(...args);
        // 빠른 경로: 403 만 검사한다
        if (response.status !== 403) return response;

        try {
            // 본문은 한 번만 읽을 수 있으므로 clone 후 검사
            const cloned = response.clone();
            const ct = (cloned.headers.get('content-type') || '').toLowerCase();
            if (!ct.includes('application/json')) return response;

            const data = await cloned.json();
            if (data && data.code === 'CSRF_INVALID') {
                notifyAndReload(data.msg);
            }
        } catch (_) {
            // JSON 파싱 실패 등은 그대로 응답 전달
        }
        return response;
    };
})();
