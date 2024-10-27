"use strict";
let controller = {};
let models = require("../models");
controller.add = async (req, res) => {
    let id = isNaN(req.body.id) ? 0 : parseInt(req.body.id);
    let quantity = isNaN(req.body.id) ? 0 : parseInt(req.body.quantity);
    let product = await models.Product.findByPk(id);

    if (product && quantity > 0) {
        req.session.cart.add(product, quantity);
    }
    return res.json({ quantity: req.session.cart.quantity });
};

controller.show = async (req, res) => {
    res.locals.cart = req.session.cart.getCart();
    return res.render("cart");
};

controller.update = async (req, res) => {
    let productId = isNaN(req.body.id) ? 0 : parseInt(req.body.id);
    let quantity = isNaN(req.body.quantity) ? 0 : parseInt(req.body.quantity);
    let product = await models.Product.findByPk(productId);

    if (product && quantity > 0) {
        let updatedItem = req.session.cart.update(productId, quantity);

        return res.json({
            quantity: req.session.cart.quantity,
            item: updatedItem,
            subtotal: req.session.cart.subtotal,
            total: req.session.cart.total,
        });
    }
    res.senStatus(204).end();
};

controller.remove = async (req, res) => {
    let productId = isNaN(req.params.id) ? 0 : parseInt(req.params.id);
    req.session.cart.remove(productId);
    return res.json({
        quantity: req.session.cart.quantity,
        subtotal: req.session.cart.subtotal,
        total: req.session.cart.total,
    });
};

module.exports = controller;
