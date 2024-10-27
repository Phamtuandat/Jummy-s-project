"use strict";

const express = require("express");
const router = express.Router();
const controller = require("../controllers/userController");
const { body, validationResult } = require("express-validator");

router.get("/checkout", controller.checkout);

router.post(
    "/placeorders",
    body("firstName").notEmpty().withMessage("First name is required"),
    body("lastName").notEmpty().withMessage("Last name is required"),
    body("mobile").notEmpty().withMessage("Mobile No is required"),
    body("email")
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Please enter a valid email address"),
    body("address").notEmpty().withMessage("Address is required"),
    (req, res, next) => {
        let errors = validationResult(req);
        if (req.body.addressId == "0" && !errors.isEmpty()) {
            let errorsArray = errors.array();
            let message = "";
            for (let i = 0; i < errorsArray.length; i++) {
                message += errorsArray[i].msg + "<br/>";
            }
            return res.render("error", { message });
        }
        next();
    },
    controller.placeOrder,
);

module.exports = router;
