  var express = require('express');
  var router = express.Router();
  const { check } = require('express-validator/check');
  const passport = require('passport');
  const users = require("../controllers/user.controller.js");
  
  router.post('/login',passport.authenticate('login'),
    [
      // Check validity
      check('email', 'Invalid email').isEmail(),
      check('password')
        .not()
        .isEmpty(),
    ],
    users.login
  );


  
  router.post('/register',
    check('email').isEmail(),
  
    users.create
  );
  
  router.get('/test', function(req, res, next) {
    res.send('respond with a resource');
  });
  
  module.exports = router;