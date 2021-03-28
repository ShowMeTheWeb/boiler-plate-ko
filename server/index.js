const express = require('express');
const app = express();
const port = 5000;
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const config = require('./config/key');

const { auth } = require('./middleware/auth');
const { User } = require('./models/User');

//bodyParser 가 Client에서 오는 정보를 서버에서 분석할 수 있게 가져옴.

//application/x-www-form-uelencoded 분석해서 가져옴
app.use(bodyParser.urlencoded({extended: true}));
//application/json 분석해서 가져옴
app.use(bodyParser.json());
app.use(cookieParser());


const mongoose = require('mongoose');
mongoose.connect(config.mongoURI, {
    useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected..'))
.catch(err => console.log(err));

app.get('/', (req, res) => res.send('Hello skchoi'));

app.post('/api/users/register', (req, res) => {
    // 회원 가입 할때 필요한 정보들을 Client에서 가져오고 DB에 넣어준다.    
    const user = new User(req.body);

    // 비밀번호 암호화 (npm i bcrypt --save) 하면 models/User.js 확인
    // userSchema.pre('save', function( next ) 되고 이 부분으로 온다.

    //MongoDB
    user.save((err, userInfo) => {
        if (err) return res.json({success: false, err})
        return res.status(200).json({
            success: true
        })
    });
});

app.post('/api/users/login', (req, res) => {
    //요청된 이메일을 데이터베이스에서 있는지 찾는다.
    User.findOne({ email: req.body.email }, (err, user) => {
        if (!user) {
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }
        
        //요청된 이메일이 데이터베이스에 있다면 비밀번호 확인
        user.comparePassword(req.body.password, (err, isMatch) => {
            if (!isMatch) {
                return res.json({
                    loginSuccess: false,
                    message: "비밀번호가 틀렸습니다."
                    });
            }

            //비밀번호가 같다면 User를 위한 Token 생성
            // npm i jsonwebtoken --save
            user.generateToken((err, user) => {
                if (err) return res.status(400).send(err);

                // token 을 저장한다. (ex. 쿠키, 로컬스토리지 etc.)
                // 쿠키에 저장하려면 npm i cookie-parser --save 설치           
                res.cookie("x_auto", user.token)
                .status(200)
                .json({
                    loginSuccess: true,
                    userId: user._id
                });
            });
        });
    });
});

// auth : 미들웨어 (request를 받고 callback function 하기 전 어떤 작업을 실행)
// role 1 어드민, role 2 특정부서 어드민, role 0 일반유저
app.get('/api/users/auth', auth, (req, res) => {
    // 여기까지 미들웨어를 통과했다면 Authentication 이 true 라는 말.
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    });
});

app.get('/api/users/logout', auth, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id} ,
        { token : "" }
        , (err, user) => {
            if (err) return res.json({ success: false, err });
            return res.status(200).send({
                success: true
            })
        });
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));

