"use strict";

const express = require("express");
const router = express.Router();
const controller = require("./../controllers/indexController");
// const models = require("./models");

// router.get("/createTables", (req, res) => {
//     models.sequelize.sync().then(() => {
//         res.send("Tables is created");
//     });
// });

router.get("/", controller.showHomepage);

router.get("/:page", controller.showPage);

module.exports = router;
