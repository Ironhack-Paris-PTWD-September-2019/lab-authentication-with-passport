const express        = require("express");
const passportRouter = express.Router();
// Require user model
const User = require("../models/user");

// Add bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// Add passport 
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

// ROUTES

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup");
});
const ensureLogin = require("connect-ensure-login");

//manque route post

passportRouter.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;


  // 1. Check username and password are not empty
  if (username === "" || password === "") {
    res.render("passport/signup", { errorMessage: "Indicate username and password" });
    return;
  }

  User.findOne({ username })
    .then(user => {
      // 2. Check user does not already exist
      if (user) {
        res.render("passport/signup", { errorMessage: "The username already exists" });
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
  res.render("passport/login");
});

passportRouter.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login"
}));


passportRouter.get("/private", (req, res, next) => {
  console.log('privqte', req.user);
  if(!req.user){
    res.redirect('/login');
    return;
  }
  res.render("passport/private", {
    user: req.user
  }) 
});

module.exports = passportRouter;