"use strict";

const models = require("../models");
const passport = require("./passport");
const bcrypt = require("bcrypt");
let controller = {};

controller.show = async (req, res) => {
    if (req.isAuthenticated()) return redirect("/");
    return res.render("login", {
        loginMessage: req.flash("loginMessage"),
        reqUrl: req.query.reqUrl,
        registerMessage: req.flash("registerMessage"),
    });
};

controller.login = async (req, res, next) => {
    let cart = req.session.cart;
    let keepSigedIn = req.body.keepSigedIn;
    let reqUrl = req.body.reqUrl || "/user/my-account";
    passport.authenticate("local-login", (error, user) => {
        if (error) {
            return next(error);
        }
        if (!user) {
            req.flash("loginMessage", "Invalid username or password.");
            return res.redirect("/user/login?reqUrl=" + req.originalUrl);
        }
        req.logIn(user, (error) => {
            if (error) {
                return next(error);
            }

            req.session.cookie.maxAge = keepSigedIn
                ? 30 * 24 * 60 * 60 * 1000
                : null; // 30 days
            req.session.cart = cart; // Restore cart from session

            return res.redirect(reqUrl);
        });
    })(req, res, next);
};
controller.logout = (req, res) => {
    let cart = req.session.cart;
    req.logout((err) => {
        if (err) return next(err);
        req.session.cart = cart;
        res.redirect("/");
    });
};
controller.register = async (req, res, next) => {
    let reqUrl = req.body.reqUrl || "/user/my-account";
    let cart = req.session.cart;
    console.log(req.body);
    passport.authenticate("local-register", (error, user) => {
        if (error) {
            return next(error);
        }
        if (!user) {
            return res.redirect("/user/login?reqUrl=" + reqUrl);
        }
        req.logIn(user, (error) => {
            if (error) {
                return next(error);
            }
            req.session.cart = cart;
            res.redirect(reqUrl);
        });
    })(req, res, next);
};

controller.showForgotPassword = (req, res) => {
    res.render("forgotPassword");
};
controller.forgotPassword = async (req, res) => {
    let email = req.body.email;
    let user = await models.User.findOne({ where: { email } });
    if (user) {
        const { sign } = require("./jwt");
        const host = req.header("host");
        const resetLink = `${req.protocol}://${host}/user/reset?token=${sign(email)}&email=${email}`;
        const { sendForgotPasswordMail } = require("./mail");
        console.log(resetLink);
        sendForgotPasswordMail(user, host, resetLink)
            .then((result) => {
                return res.render("forgotPassword", { done: true });
            })
            .catch((error) => {
                console.error("Error sending email", error);
                return res.render("forgotPassword", {
                    message: "Error sending email, please try again",
                });
            });
    } else {
        res.render("forgotPassword", { message: "Email does not exist!" });
    }
};
controller.showResetPassword = (req, res) => {
    let { token, email } = req.query;
    let { verify } = require("./jwt");
    if (verify(token)) {
        return res.render("resetPassword", { email, token });
    } else {
        res.render("resetPassword", { expired: true });
    }
};
controller.resetPassword = async (req, res) => {
    let { password, token, email } = req.body;
    let hashedPassport = bcrypt.hashSync(password, bcrypt.genSaltSync(8));
    let { verify } = require("./jwt");
    if (verify(token)) {
        models.User.update(
            { password: hashedPassport },
            { where: { email: email } },
        )
            .then((result) => {
                return res.render("resetPassword", { done: true });
            })
            .catch((error) => {
                console.error("Error resetting password", error);
                return res.render("resetPassword", {
                    message: "Error resetting password, please try again",
                });
            });
    } else {
        res.render("resetPassword", { expired: true });
    }
};
controller.isLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect("/user/login?reqUrl=" + req.originalUrl);
};
module.exports = controller;
