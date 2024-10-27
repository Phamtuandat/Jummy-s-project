"use strict";

const controller = {};
const models = require("../models");

controller.showHomepage = async (req, res) => {
    const Brand = models.Brand;
    const brands = await Brand.findAll();
    const Category = models.Category;
    const categories = await Category.findAll();
    const secondArray = categories.splice(2, 2);
    const thirdArray = categories.splice(1, 1);

    const featureProducts = await models.Product.findAll({
        attributes: ["id", "name", "imagePath", "stars", "price", "oldPrice"],
        order: [["stars", "DESC"]],
        limit: 10,
    });
    const recentProduct = await models.Product.findAll({
        order: [["createdAt", "DESC"]],
        attributes: ["id", "name", "imagePath", "stars", "price", "oldPrice"],
        limit: 10,
    });
    res.locals.recentProduct = recentProduct;
    res.locals.featureProducts = featureProducts;
    res.locals.categoryArray = [categories, secondArray, thirdArray];
    res.render("index", { brands });
};
controller.showPage = (req, res, next) => {
    console.log(req.params.page);
    const pages = [
        "cart",
        "product-list",
        "product-detail",
        "wishlist",
        "checkout",
        "contact",
        "login",
        "my-account",
    ];
    if (pages.includes(req.params.page)) return res.render(req.params.page);
    next();
};
module.exports = controller;
