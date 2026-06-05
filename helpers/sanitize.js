// 본문(bodyContent) HTML sanitize 정책.
// Toast UI Editor가 출력하는 HTML을 받아 XSS 위험 요소를 제거한 안전한 HTML로 반환한다.
//
// 정책 요점:
//  - 텍스트 서식(굵게/기울임/밑줄/취소선/제목/문단/줄바꿈) 허용
//  - 목록·번호 리스트·인용·코드·코드블록 허용
//  - 표(table/thead/tbody/tr/th/td) 허용
//  - 링크(a) 허용 — http/https/mailto만, 자동으로 noopener·noreferrer 부여
//  - 본문 내 <img> 차단 (이미지는 첨부파일 기능 사용)
//  - script, iframe, object, embed, form, input, button, style 등 차단
//  - 이벤트 핸들러 속성(onclick 등) 전부 차단
//  - javascript:, data: URL 차단 (data:image도 본문에는 미허용)
//  - style 속성은 색상/배경/정렬/굵기/장식 정도로 제한
//
// 입력이 비어있거나 문자열이 아니면 빈 문자열을 반환.

const sanitizeHtml = require('sanitize-html');

// Toast UI Editor 출력에 등장하는 클래스/스타일을 고려한 화이트리스트
const BODY_HTML_OPTIONS = {
    allowedTags: [
        'p', 'br', 'hr', 'div', 'span',
        'strong', 'b', 'em', 'i', 'u', 's', 'del', 'mark', 'sub', 'sup',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li',
        'blockquote', 'code', 'pre',
        'a',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
        // CKEditor 5 는 표/이미지를 <figure><table>...</table></figure> 또는
        // <figure><img></figure> 로 출력한다. figure/figcaption 을 허용해야
        // 본문 보기·인쇄 시 구조가 보존된다.
        'figure', 'figcaption',
        // CKEditor 5 의 TableColumnResize 가 컬럼 너비를
        // <colgroup><col style="width:..."></colgroup> 로 출력하므로 보존 필요.
        'colgroup', 'col'
    ],
    allowedAttributes: {
        // 모든 태그에 class 와 Quill 의 data-list 속성을 허용.
        //   - Quill 은 리스트 마커를 일반 <ol><li> 가 아니라 <li data-list="ordered|bullet|checked">
        //     로 출력하고, 들여쓰기·정렬·코드블록 등은 ql-indent-N / ql-align-* / ql-syntax 같은
        //     클래스로 표현한다. 이 속성들이 잘리면 VIEW 모드에서 번호·정렬·들여쓰기가 사라진다.
        //   - class 값 자체는 별도로 allowedClasses 화이트리스트로 제한해 임의 클래스 주입을 막는다.
        '*':   ['class', 'data-list', 'data-checked'],
        a:     ['href', 'title', 'target', 'rel'],
        // table / td / th / col 에 style 허용 — CKEditor 의 너비 정보(width:%, px)를 보존하기 위해.
        td:    ['colspan', 'rowspan', 'align', 'valign', 'style'],
        th:    ['colspan', 'rowspan', 'align', 'valign', 'scope', 'style'],
        table: ['border', 'cellpadding', 'cellspacing', 'style'],
        col:      ['span', 'style'],
        colgroup: ['span', 'style'],
        figure:   ['style'],
        span:  ['style'],
        p:     ['style'],
        div:   ['style'],
        li:    ['style'],
        // 인라인 코드/코드 블록 등 — 위 와일드카드의 class 와 합쳐짐
        code: [],
        pre:  []
    },
    // 허용할 class 값 — Quill / CKEditor 5 가 실제로 출력하는 패턴만.
    //   Quill : ql-indent-*, ql-align-*, ql-syntax, ql-size-*, ql-font-*, ql-bg-*, ql-color-*
    //   CKEd5 : 'table', 'image', 'image-style-*', 'image_resized', 'media',
    //           'text-tiny|small|big|huge', 'todo-list', 'image-inline'
    //   공통  : language-* (코드블록)
    allowedClasses: {
        '*': [
            // Quill (legacy 호환)
            /^ql-indent-[1-9]$/,
            /^ql-align-(center|right|justify)$/,
            /^ql-direction-rtl$/,
            'ql-syntax',
            /^ql-size-(small|large|huge)$/,
            /^ql-font-[\w-]+$/,
            /^ql-bg-[\w-]+$/,
            /^ql-color-[\w-]+$/,
            // CKEditor 5
            'table', 'image', 'image-inline', 'image_resized', 'media',
            /^image-style-[\w-]+$/,
            /^text-(tiny|small|big|huge)$/,
            'todo-list', 'todo-list__label',
            // 공통
            /^language-[\w-]+$/
        ]
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesAppliedToAttributes: ['href'],
    allowProtocolRelative: false,

    // style 속성에 허용할 속성과 값
    allowedStyles: {
        '*': {
            // 색상: 영문 색상명, hex(#abc / #aabbcc), rgb(...)
            'color':            [/^#(0x)?[0-9a-f]+$/i, /^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/, /^[a-z\-]+$/i],
            'background-color': [/^#(0x)?[0-9a-f]+$/i, /^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/, /^[a-z\-]+$/i],
            'text-align':       [/^(left|right|center|justify)$/],
            'font-weight':      [/^(bold|normal|[1-9]00)$/],
            'font-style':       [/^(italic|normal)$/],
            'text-decoration':  [/^(underline|line-through|none)$/],
            // CKEditor TableColumnResize / TableProperties / TableCellProperties 가
            // 표·열·셀에 너비/높이/패딩 정보를 부여한다. 단위는 %, px, em, rem, pt 만 허용.
            'width':            [/^[0-9.]+(%|px|em|rem|pt)$/],
            'min-width':        [/^[0-9.]+(%|px|em|rem|pt)$/],
            'max-width':        [/^[0-9.]+(%|px|em|rem|pt)$/],
            'height':           [/^[0-9.]+(%|px|em|rem|pt)$/],
            'padding':          [/^[0-9.\s]+(px|em|rem|pt)$/],
            'padding-top':      [/^[0-9.]+(px|em|rem|pt)$/],
            'padding-right':    [/^[0-9.]+(px|em|rem|pt)$/],
            'padding-bottom':   [/^[0-9.]+(px|em|rem|pt)$/],
            'padding-left':     [/^[0-9.]+(px|em|rem|pt)$/],
            'border':           [/^[0-9.]+(px|em|rem|pt)\s+(solid|dashed|dotted|double|none)\s+#?[0-9a-fA-F]+$/, /^none$/],
            'border-style':     [/^(solid|dashed|dotted|double|none)$/],
            'border-width':     [/^[0-9.]+(px|em|rem|pt)$/],
            'border-color':     [/^#(0x)?[0-9a-f]+$/i, /^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/, /^[a-z\-]+$/i],
            'vertical-align':   [/^(top|middle|bottom|baseline)$/],
            // CKEditor 의 표 정렬(좌/가운데/우)은 figure.table 에 float / margin 으로 표현된다.
            // 가운데 정렬: style="margin: 0 auto" 또는 "margin-left:auto;margin-right:auto"
            // 우측 정렬  : style="float:right"
            // 좌측 정렬  : style="float:left"
            'float':            [/^(left|right|none)$/],
            // margin shorthand — 1~4 value, 각 value 는 'auto' 또는 '0' 또는 숫자+단위.
            // 예: 'auto', '0 auto', '0.4em auto', '0 auto 0 auto', '0.4em 0 0.4em auto'
            'margin':           [/^(?:auto|0|[\d.]+(?:px|em|rem|pt))(?:\s+(?:auto|0|[\d.]+(?:px|em|rem|pt))){0,3}$/],
            'margin-left':      [/^(auto|[0-9.]+(px|em|rem|pt))$/],
            'margin-right':     [/^(auto|[0-9.]+(px|em|rem|pt))$/],
            'margin-top':       [/^(auto|[0-9.]+(px|em|rem|pt))$/],
            'margin-bottom':    [/^(auto|[0-9.]+(px|em|rem|pt))$/],
            'clear':            [/^(left|right|both|none)$/]
        }
    },

    // 링크 변환: target=_blank + rel=noopener noreferrer 자동 부여 (외부 링크 보안)
    transformTags: {
        'a': sanitizeHtml.simpleTransform('a', {
            target: '_blank',
            rel:    'noopener noreferrer'
        })
    },

    // 비허용 태그는 텍스트만 남기고 제거 (안의 콘텐츠는 보존)
    disallowedTagsMode: 'discard',

    // 자기-닫는 태그
    selfClosing: ['br', 'hr'],

    // 빈 텍스트 노드/공백 보존
    nonTextTags: ['style', 'script', 'textarea', 'noscript']
};

/**
 * 본문 HTML을 sanitize 한다.
 *  - null/undefined/빈 문자열 → ''
 *  - 문자열이 아니면 String(...) 으로 강제 변환 후 처리
 *  - 결과 길이가 0이면 그대로 ''
 *
 * 사용자가 의도적으로 넣은 빈 단락(공백 줄)도 보존한다.
 * CKEditor 가 만드는 <p>&nbsp;</p> 등은 그대로 두고, VIEW 화면의 간격은
 * CSS(.ck-content p {margin}) 로 일관되게 처리한다.
 */
function sanitizeBodyHtml(input) {
    if (input == null) return '';
    const str = typeof input === 'string' ? input : String(input);
    if (!str.trim()) return '';
    return sanitizeHtml(str, BODY_HTML_OPTIONS);
}

/**
 * 본문이 HTML인지(태그가 한 개라도 있는지) 빠르게 판정.
 * 기존 plain text 데이터를 화면에서 분기 표시하는 데 사용.
 *  - true: HTML로 간주, 렌더는 sanitize된 .innerHTML
 *  - false: plain text, escape 후 \n→<br>
 */
function looksLikeHtml(input) {
    if (typeof input !== 'string' || !input) return false;
    // 단순 휴리스틱: 열린 태그가 한 개라도 있으면 HTML로 본다.
    // sanitize는 어차피 서버에서 거치므로 false-positive 위험은 낮다.
    return /<[a-z][\s\S]*?>/i.test(input);
}

module.exports = {
    sanitizeBodyHtml,
    looksLikeHtml
};
