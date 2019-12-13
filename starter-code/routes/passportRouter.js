const express        = require("express");
const passportRouter = express.Router();

const User = require('../models/user.js');

const bcrypt = require("bcrypt");
const bcryptSalt = 10;

const passport = require("passport");

// SIGNUP
passportRouter.get("/signup", (req,res,next)=>{
  res.render('passport/signup'); 
});

passportRouter.post("/signup", (req,res,next)=>{
  const username = req.body.username;
  const password = req.body.password;

  if (username === "" || password === "") {
    res.render("passport/signup", { errorMessage: "Indicate username and password" });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render("passport/signup", { errorMessage: "The username already exists" });
        return;
      }

      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
        username,
        password: hashPass
      });

      newUser.save()
        .then(user => res.redirect("/"))
        .catch(err => next(err));
    })
    .catch(err => next(err));
});

//LOGIN
passportRouter.get("/login", (req,res,next)=>{
  res.render('passport/login', { "errorMessage": req.flash("error") }); 
});

passportRouter.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true
}));

//PRIVATE PAGE
passportRouter.get("/private-page", (req, res) => {
  if (!req.user) {
    res.redirect('/login');
    return;
  }
  
  res.render("passport/private", { user: req.user });
});

//LOGOUT
passportRouter.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});


module.exports = passportRouter;