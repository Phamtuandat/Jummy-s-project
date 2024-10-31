"use strict";
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const models = require("../models");

passport.serializeUser((user, done) => {
    done(null, user.id); // Serializes user ID to the session
});

passport.deserializeUser((id, done) => {
    models.User.findByPk(id) // Deserializes user from the session
        .then((user) => done(null, user))
        .catch((err) => done(err));
});

passport.use(
    "local-login",
    new LocalStrategy(
        {
            usernameField: "email",
            passwordField: "password",
            passReqToCallback: true,
        },
        async (req, email, password, done) => {
            // Fixed parameter
            if (email) {
                email = email.toLowerCase();
            }
            try {
                if (!req.user) {
                    const user = await models.User.findOne({
                        where: { email: email },
                    });
                    if (!user) {
                        return done(
                            null,
                            false,
                            req.flash(
                                "loginMessage",
                                "The Email Is Not Existed.",
                            ),
                        );
                    }

                    const isMatch = await bcrypt.compare(
                        password,
                        user.password,
                    );
                    if (!isMatch) {
                        return done(
                            null,
                            false,
                            req.flash("loginMessage", "Incorrect password."),
                        );
                    }

                    return done(null, user);
                }
                return done(null, req.user);
            } catch (error) {
                return done(error);
            }
        },
    ),
);
passport.use(
    "local-register",
    new LocalStrategy(
        {
            usernameField: "email",
            passwordField: "password",
            passReqToCallback: true,
        },
        async (req, email, password, done) => {
            if (email) {
                email = email.toLowerCase();
            }
            try {
                let user = await models.User.findOne({
                    where: { email: email },
                });
                if (user) {
                    return done(
                        null,
                        false,
                        req.flash(
                            "registerMessage",
                            "The Email Is Already Existed.",
                        ),
                    );
                }
                const hashedPassword = await bcrypt.hash(
                    password,
                    bcrypt.genSaltSync(8),
                );
                user = await models.User.create({
                    email,
                    password: hashedPassword,
                    firstName: req.body.firstName,
                    lastName: req.body.lastName,
                    mobile: req.body.mobile,
                });
                return done(
                    null,
                    false,
                    req.flash(
                        "registerMessage",
                        "Register Successfully. Please Login Now.",
                    ),
                );
            } catch (error) {
                return done(error);
            }
        },
    ),
);

module.exports = passport;
