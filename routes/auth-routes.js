const express = require("express");
const authRoutes = express.Router();

// User Model
const User = require("../models/user");

// Bcrypt to Encrypt Passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// Route to Handle Signup Form Display
authRoutes.get("/signup", (req, res, next) => {
    res.render("auth/signup");
}); 

// Route to Handle Signup Form Submission
authRoutes.post("/signup", (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    // Validation 1 - Check for whether user has provided
    // username and password
    if (username === "" || password === "") {
        res.render("auth/signup", { message: "Indicate username and password" });
        return;
    }

    User.findOne({ username }, "username", (err, user) => {
        
        // Validation 2 - Check whether User already exists in the database
        if (user != null) {
            res.render("auth/signup", { message: "The username already exists" });
            return;
        }

        // Encrypt password
        const salt = bcrypt.genSaltSync(bcryptSalt);
        const hashPass = bcrypt.hashSync(password, salt);

        // Generate new User with encrypted password
        const newUser = new User({
            username,
            password: hashPass
        });

        // Save the new User to the database
        newSave.save((err) => {
            if (err) {
                res.render("auth/signup", { message: "Something went wrong" });
            } else {
                res.redirect("/");
            }
        });
    });
});

module.exports = authRoutes;