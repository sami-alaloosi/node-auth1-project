const router = require("express").Router();
const bcryptjs = require("bcryptjs");

const Users = require("../users/users-model.js");

router.post("/register", (req, res) => {
    const userInfo = req.body;
    const isValid = validateUser(userInfo);

    if (isValid) {
        // hash the password before saving the user to the database
        const rounds = process.env.BCRYPT_ROUNDS || 4;
        const hash = bcryptjs.hashSync(userInfo.password, rounds);
        userInfo.password = hash;

        Users.add(userInfo)
            .then(inserted => {
                res.status(201).json({ data: inserted });
            })
            .catch(error => {
                res.status(500).json({ message: error.message });
            });
    } else {
        res.status(400).json({
            message: "Invalid information, plese verify and try again",
        });
    }
});

router.post("/login", (req, res) => {
    const creds = req.body;
    const isValid = validateCredentials(creds);

    if (isValid) {
        Users.findBy({ username: creds.username })
            .then(([user]) => {
                if (user && bcryptjs.compareSync(creds.password, user.password)) {
                    req.session.username = user.username;
                    req.session.role = user.role;

                    res.status(200).json({
                        message: `welcome ${creds.username}`,
                    });
                } else {
                    // no user by that username
                    res.status(401).json({ message: "you cannnot pass!!" });
                }
            })
            .catch(error => {
                res.status(500).json({ message: error.message });
            });
    } else {
        res.status(400).json({
            message: "Invalid information, plese verify and try again",
        });
    }
});

router.get("/logout", (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                res.status(500).json({
                    message: "you can check out any time you like, but you can never leave",
                });
            } else {
                res.status(204).end();
            }
        });
    } else {
        res.status(204).end();
    }
});

function validateUser(user) {
    // has username, password and role
    return user.username && user.password  ? true : false;
}

function validateCredentials(creds) {
    // has username, password and role
    return creds.username && creds.password ? true : false;
}

module.exports = router;
