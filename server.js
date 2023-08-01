const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv").config();  // enable our code to read from ".env" file
const userService = require("./user-service.js");
const jwt = require('jsonwebtoken');
const passport = require("passport");
const passportJWT = require("passport-jwt");

const HTTP_PORT = process.env.PORT || 8080;

// JSON Web Token Setup
let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

// Configure its options
let jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
  secretOrKey: process.env.JWT_SECRET,  // long unguessable string we stored in .env
};

let strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
    console.log('payload received', jwt_payload);

    if (jwt_payload) {
        // The following will ensure that all routes using 
        // passport.authenticate have a req.user._id, req.user.userName values 
        // that matches the request payload data
        next(null, { _id: jwt_payload._id, 
            userName: jwt_payload.userName
        }); 
    } else {
        next(null, false);
    }
});


passport.use(strategy);

app.use(express.json());    // ensure that our server can parse the JSON provided in the request body for some of our routes
app.use(cors());            // Add support for CORS
app.use(passport.initialize());

app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
    .then((msg) => {
        res.json({ "message": msg });
    }).catch((msg) => {
        res.status(422).json({ "message": msg });
    });
});

app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
    .then((user) => {
        // user is valid, use user obj to generate payload obj w/ 2 properties (_id, userName)

        let payload = { 
            _id: user._id,
            userName: user.userName
        };
        
        // sign payload using "jwt" w/ the secret from process.env.JWT_SECRET
        let token = jwt.sign(payload, jwtOptions.secretOrKey);

        // return JSON message to client and include token property containing signed token
        res.json({ "message": "login successful", "token": token });

    }).catch(msg => {
        res.status(422).json({ "message": msg });
    });
});

app.get("/api/user/favourites",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getFavourites(req.user._id)
    .then(data => {
        res.json(data);
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })

});

app.put("/api/user/favourites/:id",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
    .then(data => {
        res.json(data)
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })
});

app.delete("/api/user/favourites/:id",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
    .then(data => {
        res.json(data)
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })
});

app.get("/api/user/history",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getHistory(req.user._id)
    .then(data => {
        res.json(data);
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })

});

app.put("/api/user/history/:id",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
    .then(data => {
        res.json(data)
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })
});

app.delete("/api/user/history/:id",passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
    .then(data => {
        res.json(data)
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })
});

userService.connect()
.then(() => {
    app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT) });
})
.catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
});