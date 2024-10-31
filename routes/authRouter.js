"use strict";

const express = require("express");
const router = express.Router();
const { body, getErrorMessage } = require("../controllers/validator");
const controller = require("../controllers/authController");

router.get("/login", controller.show);
router.post(
    "/login",
    body("email")
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Invalid email"),
    body("password").trim().notEmpty().withMessage("Password is required"),
    (req, res, next) => {
        let errorsMessage = getErrorMessage(req);
        if (errorsMessage) {
            return res.render("/login", { loginMessage: errorsMessage });
        }
        next();
    },
    controller.login,
);

router.get("/logout", controller.logout);
router.post(
    "/register",
    body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Invalid email"),
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("confirmPassword")
        .trim()
        .notEmpty()
        .withMessage("confirm password is required")
        .custom((confirmPassword, { req }) => {
            if (confirmPassword !== req.body.password) {
                throw new Error("Passwords do not match");
            }
            return true;
        }),
    body("firstName").trim().notEmpty().withMessage("First is required"),
    body("password")
        .matches(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/)
        .withMessage(
            "Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters",
        ),
    (req, res, next) => {
        let errorsMessage = getErrorMessage(req);
        if (errorsMessage) {
            return res.render("login", {
                registerMessage: errorsMessage.msg,
            });
        }
        next();
    },
    controller.register,
);
router.get("/forgot", controller.showForgotPassword);
router.post(
    "/forgot",
    body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Invalid email"),
    (req, res, next) => {
        let errorsMessage = getErrorMessage(req);
        if (errorsMessage) {
            return res.render("forgotPassword", {
                message: errorsMessage.msg,
            });
        }
        next();
    },
    controller.forgotPassword,
);

router.get("/reset", controller.showResetPassword);
router.post(
    "/reset",
    body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Invalid email"),
    body("password")
        .matches(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/)
        .withMessage(
            "Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters",
        ),
    body("confirmPassword")
        .trim()
        .notEmpty()
        .withMessage("confirm password is required")
        .custom((confirmPassword, { req }) => {
            if (confirmPassword !== req.body.password) {
                throw new Error("Passwords do not match");
            }
            return true;
        }),
    (req, res, next) => {
        let errorsMessage = getErrorMessage(req);
        if (errorsMessage) {
            return res.render("reset", {
                message: errorsMessage.msg,
            });
        }
        next();
    },
    controller.resetPassword,
);

module.exports = router;
