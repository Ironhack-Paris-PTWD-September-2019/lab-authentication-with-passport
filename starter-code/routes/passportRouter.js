const express        = require("express");
const passportRouter = express.Router();
const User = require("../models/user");
const passport = require("passport");

const bcrypt = require("bcrypt");
const bcryptSalt = 10;


passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login")
});

passportRouter.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup")
});

passportRouter.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === "" || password === "") {
    res.render("/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username })
  .then(user => {
    if (user !== null) {
      res.render("/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const securePWD = bcrypt.hashSync(password, salt);

    const newUser = new User({
      username,
      password: securePWD
    });

    newUser.save((err) => {
      if (err) {
        res.render("/signup", { message: "Something went wrong" });
      } else {
        res.redirect("/private-page");
      }
    });
  })
  .catch(error => {
    next(error)
  })
});

passportRouter.get("/private-page", (req, res) => {
  if (req.user)
  {res.render("passport/private", { user: req.user })};
});

module.exports = passportRouter;
