const express        = require("express");
const passportRouter = express.Router();
// Require user model
const User = require(`../models/user`);

// Add bcrypt to encrypt passwords
const bcrypt = require(`bcrypt`);
const bcryptSalt = 10;
const salt = bcrypt.genSaltSync(bcryptSalt);

// Add passport 
const passport = require(`passport`);

passportRouter.get(`/signup`, (req,res,next) => {
  res.render(`passport/signup`);
});

passportRouter.post(`/signup`, (req,res,next) => {
  const { username, password } = req.body;

  if(username.length <= 0 || password.length <= 0) {
    res.render(`passport/signup`, {
      errorMessage: `Please fill both username and password`
    });
    return;
  }
  
  const hashPass = bcrypt.hashSync(password, salt);

  User.create({
    username,
    password: hashPass
  })
    .then(
      res.redirect(`/`)
    )
    .catch(err => next(err));
});

passportRouter.get(`/login`, (req,res,next) => {
  res.render(`passport/login`)
});

passportRouter.post(`/login`, passport.authenticate(`local`, {
  successRedirect: `/private-page`,
  failureRedirect: `/login`
}));

passportRouter.get(`/private-page`, (req, res) => {
  res.render(`passport/private`, { user: req.user });
});

module.exports = passportRouter;