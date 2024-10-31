"use strict";
/** @type {import('sequelize-cli').Migration} */
const bcrypt = require("bcrypt");
const models = require("../models");

module.exports = {
    async up(queryInterface, Sequelize) {
        try {
            // Fetch all users
            let users = await models.User.findAll();

            // Prepare array for updated users with hashed passwords
            let updatedUsers = users.map((user) => ({
                id: user.id,
                password: bcrypt.hashSync("Demo@123", 8),
            }));

            // Bulk update users with new hashed passwords
            await models.User.bulkCreate(updatedUsers, {
                updateOnDuplicate: ["password"],
            });
        } catch (error) {
            console.error("Error updating passwords:", error);
        }
    },

    async down(queryInterface, Sequelize) {
        // Add rollback logic here if necessary
    },
};
