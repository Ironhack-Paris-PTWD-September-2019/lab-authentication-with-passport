const express        = require("express");
const passportRouter = express.Router();
const User = require('../models/user')
const bcrypt = require('bcrypt')
const bcryptSalt = 10;
const passport = require("passport");
// Require user model

// Add bcrypt to encrypt passwords

// Add passport 


const ensureLogin = require("connect-ensure-login");


passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

passportRouter.get("/signup", (req, res) => {
  res.render("passport/signup", { user: req.user });
});

passportRouter.post('/signup' , (req , res , next) => {
  const username = req.body.username
  const password = req.body.password

  if (username === "" || password === "") {
    res.render('passport/signup' , {errorMessage : "Veuillez entrer un nom d'utilisateur et mot de passe"});
      return
  }
  User.findOne({username})
    .then(user => {
      if(user){
        res.render('passport/signup' , {errorMessage : "Veuillez entrer un nom d'utilisateur et mot de passe"});
          return
      }
    })
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      User.create({
        username : username,
        password : hashPass
      })
      .then(user => {
        res.redirect('/')
      })
      .catch(error => {
        next(error)
      })
})

passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login");
});

passportRouter.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login"
}));

passportRouter.get("/private-page", (req, res) => {
  if (!req.user) {
    res.redirect('/login'); // not logged-in
    return;
  }
  
  // ok, req.user is defined
  res.render("passport/private", { user: req.user });
});


module.exports = passportRouter;