const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcryptjs = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("../users/users-router.js");
const authRouter = require("../auth/auth-router.js"); /// <<<<<
const connection = require("../database/connection.js");

const server = express();

const sessionConfig = {
    name: "monster",
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    resave: false,
    saveUninitialized: true, // ask the client if it's ok to save cookies (GDPR compliance)
    cookie: {
        maxAge: 1000 * 60 * 60, // in milliseconds
        secure: process.env.USE_SECURE_COOKIES || false, // true means use only over https connections
        httpOnly: true, // true means the JS code on the clients CANNOT access this cookie
    },
    store: new KnexSessionStore({
        knex: connection, // knex connection to the database
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 1000 * 60 * 60, // remove expired sessions every hour
    }),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); //  <<< turn un sessions, adds a req.session object

server.use("/api/users", protected, usersRouter);
server.use("/api/auth", authRouter); //<<<<<<

server.get("/", (req, res) => {
    const password = req.headers.password;

    // the higher the rounds number the more secure the password is
    const rounds = process.env.BCRYPT_ROUNDS || 4; // as high as possible in production
    const hash = bcryptjs.hashSync(password, rounds);
    res.json({ api: "up", password, hash });
});

function protected(req, res, next) {
    if (req.session.username) {
        next();
    } else {
        res.status(401).json({ you: "cannot pass!" });
    }
}

module.exports = server;

// $2a$04$iG7YcXpTgyjvpDSgDmVRx.IH3npPl/LuBrFD5KvGgxQxl3DU/fSBi
// $2a$04$DdE9GAWd.6p1Sj2JmVGFh.pRrLoDRBFG2Hmmw9CkzvnGM.xPCBviO
