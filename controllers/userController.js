"use strict";

let controller = {};
const { where } = require("sequelize");
const models = require("../models");

controller.checkout = async (req, res) => {
    if (req.session.cart.quantity > 0) {
        let userId = 1;
        res.locals.address = await models.Address.findAll({
            where: { userId },
        });
        res.locals.cart = req.session.cart.getCart();
        return res.render("checkout");
    }
    res.redirect("/products");
};
controller.placeOrder = async (req, res) => {
    let userId = 1;
    // let {addressId, payment} = req.body;
    let addressId = isNaN(req.body.addressId)
        ? 0
        : parseInt(req.body.addressId);

    let address = await models.Address.findByPk(addressId);
    if (!address) {
        address = await models.Address.create({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            mobile: req.body.phone,
            address: req.body.address,
            userId,
            state: req.body.state,
            country: req.body.country,
            city: req.body.city,
            zipCode: req.body.zipCode,
            isDefault: req.body.isDefault,
        });
    }
    let cart = req.session.cart;
    cart.paymentMethod = req.body.payment;
    cart.shippingAddress = `${address.firstName} ${address.lastName}, Email: ${address.email}, Mobile: ${address.mobile}, Address: ${address.address}, ${address.city}, ${address.country}, ${address.state}, ${address.zipCode}`;
    switch (req.body.payment) {
        case "COD":
            saveOders(req, res, "PAID");
            break;
        case "PAYPAL":
            saveOders(req, res, "UNPAID");
            break;
    }
};

async function saveOders(req, res, status) {
    let userId = 1;
    let { items, ...orders } = req.session.cart.getCart();
    console.log(items);
    let order = await models.Order.create({
        ...orders,
        userId,
        status,
    });
    let orderDetail = [];
    items.forEach((item) => {
        orderDetail.push({
            orderId: order.id,
            productId: item.product.id,
            quantity: item.quantity,
            price: item.product.price,
            total: item.total,
        });
    });
    await models.OrderDetail.bulkCreate(orderDetail);
    req.session.cart.clear();
    return res.render("error", { message: "Thank you for your order!" });
}
module.exports = controller;
