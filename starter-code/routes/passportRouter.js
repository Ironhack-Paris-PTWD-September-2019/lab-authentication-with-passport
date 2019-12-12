const express        = require("express");
const passportRouter = express.Router();
const passport = require("passport");

// Require user model
const User = require("../models/user");
// Add bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// Add passport 

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup");
});

passportRouter.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  // 1. Check username and password are not empty
  if (username === "" || password === "") {
    res.render("auth/signup", { errorMessage: "Indicate username and password" });
    return;
  }

  User.findOne({ username })
    .then(user => {
      // 2. Check user does not already exist
      if (user) {
        res.render("auth/signup", { errorMessage: "The username already exists" });
        return;
      }

      // Encrypt the password
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      //
      // Save the user in DB
      //

      const newUser = new User({
        username,
        password: hashPass
      });

      newUser.save()
        .then(user => res.redirect("/"))
        .catch(err => next(err))
      ;
        
    })
    .catch(err => next(err))
  ;
});

passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login", { "errorMessage": req.flash("error") });
});

passportRouter.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true 
}));

const ensureLogin = require("connect-ensure-login");


passportRouter.get("/private-page", ensureLogin.ensureLoggedIn('/login'), (req, res) => {
  res.render("passport/private", { user: req.user });
});


passportRouter.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});


module.exports = passportRouter;