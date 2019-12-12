const express        = require("express");
const passportRouter = express.Router();

// Require user model
const User=require('../models/user.js');

// Add bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;


// Add passport 
const passport = require("passport");


passportRouter.get("/signup", (req,res,next)=>{
  res.render('passport/signup'); 
});

passportRouter.post("/signup", (req,res,next)=>{
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

passportRouter.get("/login", (req,res,next)=>{
  res.render('passport/login'); 
});

passportRouter.post("/login", (req,res,next)=>{
  passport.authenticate("local", (err, theUser, failureDetails) => {
    if (err) {
      // Something went wrong authenticating user
      return next(err);
    }
  
    if (!theUser) {
      // Unauthorized, `failureDetails` contains the error messages from our logic in "LocalStrategy" {message: '…'}.
      req.flash('error', 'Wrong password or username');
      res.render('passport/login', { messages: req.flash('error') }); 
      return;
    }

    // save user in session: req.user
    req.login(theUser, (err) => {
      if (err) {
        // Session save went bad
        return next(err);
      }

      // All good, we are now logged in and `req.user` is now set
      res.redirect('/')
    });
  })(req, res, next);


});

passportRouter.get("/private-page", (req, res,next) => {
  if (!req.user) {
    res.redirect('/login'); // not logged-in
    return;
  }
  
  // ok, req.user is defined
  res.render("passport/private", { user: req.user });
});

module.exports = passportRouter;