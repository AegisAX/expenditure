function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate');
        return next();
    }
    // [진단] 어떤 요청이 로그인 미보유로 차단됐는지. 로그인 직후 race 진단용.
    const cookieHeader = req.headers.cookie || '';
    const hasSidCookie = cookieHeader.includes('connect.sid');
    console.warn(`[Auth Redirect] sessionID=${req.sessionID}  cookie.connect.sid?=${hasSidCookie ? 'YES' : 'NO'}  ${req.method} ${req.originalUrl}`);
    res.redirect('/login');
}

function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'Admin') return next();
    res.redirect('/login');
}

module.exports = { requireLogin, requireAdmin };