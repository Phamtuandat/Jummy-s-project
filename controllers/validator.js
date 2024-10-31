"use strict";

const { body, validationResult } = require("express-validator");

function getErrorMessage(req) {
    let err = validationResult(req);
    if (!err.isEmpty()) {
        let errors = err.array();
        return errors.reduce((message, error) => {
            return message + error.message + "\n";
        });
    }
    return null;
}

module.exports = { body, getErrorMessage };
