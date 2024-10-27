"use strict";

const helper = {};

helper.createStarList = (stars) => {
    let star = Math.floor(stars);
    let half = stars - star;
    let starHtml = '<div class="ratting">';
    for (let i = 0; i < star; i++) {
        starHtml += '<i class="fa fa-star"></i>';
    }
    if (half > 0) {
        starHtml += '<i class="fa fa-star-half-o"></i>';
    }
    for (let i = star; i < 5; i++) {
        starHtml += '<i class="fa fa-star-o"></i>';
    }
    starHtml += "</div>";

    return starHtml;
};

module.exports = helper;
