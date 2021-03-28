const { User } = require('../models/User');

let auth = (req, res, next) => {
    // 인증 처리를 하는곳
    // 클라이언트 쿠키에서 토큰을 가져온다.
    let token = req.cookies.x_auto;

    // 토큰을 복호화하고 유저를 찾는다. // 유저가 있으면 인증 OK, 없으면 인증 NO
    User.findbyToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json({ isAuto: false, error: true });

        req.token = token;
        req.user = user;
        next();
    })
}

module.exports = {auth};