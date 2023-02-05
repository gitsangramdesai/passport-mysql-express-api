const db = require("../models");
const User = db.users;
const Op = db.Sequelize.Op;
const bcrypt = require('bcrypt');
const passport = require('passport');
const { validationResult } = require('express-validator/check');
const jwt = require('jsonwebtoken');
const secret = require('../config/jwtConfig');

exports.login = async (req, res,next) => {
    passport.authenticate('login',{ session: false },
  
        // eslint-disable-next-line consistent-return
        // eslint-disable-next-line no-unused-vars
        async (err, user, _info) => {
          try {
            if (err || !user) {
              return res.status(401).json({
                error: {
                  code: `USR_10`,
                  message: `Error occurred`,  // eslint-disable-line
                  field: `facebook login,  `,
                  status: 401,
                },
              });
            }
            // eslint-disable-next-line consistent-return
            req.login(user, { session: false }, async error => {
              if (error) return next(error);
  
              // We don't want to store the sensitive information such as the
              // user password in the token so we pick only the email and id
              const payload = {
                email: user.email,
              };
              // eslint-disable-next-line consistent-return
              jwt.sign(payload, `${secret}`, { expiresIn: '24h' }, (errr, token) => {
                if (errr) {
                  return res.status(400).json({
                    error: {
                      code: `USR_10`,
                      message: `Error occurred`,  // eslint-disable-line
                      field: `jwt signing`,
                      status: 400,
                    },
                  });
                }
  
                return res.status(200).json({
                  customer: {
                    user_id: user.id,
                    email: user.email
                  },
  
                  accessToken: `Bearer ${token}`,
                  expiresIn: `24h`,
                });
              });
            });
          } catch (error) {
            return next(error);
          }
        }
      )(req, res, next);
}

exports.create =async (req, res, next) => {
    try {
      const errors = validationResult(req); // Finds the validation errors in this request and wraps them in an object with handy functions

      if (!errors.isEmpty()) {
        return res.status(422).json({
          error: {
            code: `USR_03`,
            message: `The email is invalid.`,  // eslint-disable-line
            field: `email`,
            status: 400,
          },
        });
      }
      const { email } = req.body;
      const { password } = req.body;

      const cust = await db.users.findOne({
        where: {
          // eslint-disable-next-line object-shorthand
          email: email,
        },
      });

      if (cust) {
        return res.status(422).json({
          error: {
            code: `USR_04`,
            message: `The email already exists.`,  // eslint-disable-line
            field: `email`,
            status: 400,
          },
        });
      }

      db.users.create({
        email,
        password
      })
        .then(user => {
          const payload = { email: user.email };

          const token = jwt.sign(payload, `${secret}`, { expiresIn: '24h' });

          return res.status(200).json({
            customer: {
              user_id: user.id,
              email: user.email
            },

            accessToken: `Bearer ${token}`,
            expiresIn: `24h`,
          });
        })
        // eslint-disable-next-line no-unused-vars
        .catch(_err => {
          return res.status(400).json({
            error: {
              code: `USR_10`,
              message: `Error occurred`,  // eslint-disable-line
              field: `register`,
              status: 400,
            },
          });
        });
    } catch (error) {
      return next(error);
    }
}

