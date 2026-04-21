function requireLogin(req, res, next) {
    if (req.session.user) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate');
        return next();
    }
    res.redirect('/login');
}

function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'Admin') return next();
    res.redirect('/login');
}

module.exports = { requireLogin, requireAdmin };