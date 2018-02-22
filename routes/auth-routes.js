const express = require("express");
const authRoutes = express.Router();
const ensureLogin = require("connect-ensure-login");

// Passport Configuration
const passport = require("passport");

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
        newUser.save((err) => {
            if (err) {
                res.render("auth/signup", { message: "Something went wrong" });
            } else {
                res.redirect("/");
            }
        });
    });
});

// Route to Display Login Form
authRoutes.get("/login", (req, res, next) => {
    res.render("auth/login", { "message": req.flash("error") });
});

// Route to Handle Login Form Submission
authRoutes.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
}));

authRoutes.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
    res.render("private", { user: req.user })
});

authRoutes.get("/logout", (req, res) => {
    req.logout();
    res.redirection("/login");
});

// OAuth - Facebook Configuration
authRoutes.get("/auth/facebook", passport.authenticate("facebook"));
authRoutes.get("/auth/facebook/callback", passport.authenticate("facebook", {
    successRedirect: "/private-page",
    failureRedirect: "/"
}));

// OAuth - Google Configuration
authRoutes.get("/auth/google", passport.authenticate("google", {
    scope: ["https://www.googleapis.com/auth/plus.login",
            "https://www.googleapis.com/auth/plus.profile.emails.read"]
}));

authRoutes.get("/auth/google/callback", passport.authenticate("google", {
    failureRedirect: "/",
    sucessRedirect: "/private-page"
}));

module.exports = authRoutes;