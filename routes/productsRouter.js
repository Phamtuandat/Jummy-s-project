"use strict";

let express = require("express");
const router = express.Router();

let controller = require("../controllers/productsController");
let cartController = require("../controllers/cartController");

router.get("/", controller.getData, controller.show);
router.get("/cart", cartController.show);
router.get("/:id", controller.getData, controller.showDetail);
router.post("/cart", cartController.add);
router.put("/cart", cartController.update);
router.delete("/cart/:id", cartController.remove);
module.exports = router;
