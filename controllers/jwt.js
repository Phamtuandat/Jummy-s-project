"use strict";

const jwt = require("jsonwebtoken");

function sign(email, expiresIn = "30m") {
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn });
    return token;
}

function verify(token) {
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        return true;
    } catch (error) {
        return false;
    }
}

module.exports = {
    sign,
    verify,
};
