// routes/auth.js
const express  = require('express');
const bcrypt   = require('bcryptjs');
const passport = require('passport');
const User     = require('../models/User');

const router = express.Router();

// ---------- REGISTER PAGE ----------
router.get('/register', (req, res) => {
  res.render('register', {
    title: 'Register',
    searchQuery: '',
    error: false
  });
});

// ---------- HANDLE REGISTER ----------
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    const existing = await User.findOne({ username });
    if (existing) {
      return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username,
      password: hashedPassword
    });

    res.redirect('/login');
  } catch (err) {
    console.error('Error registering user:', err);
    res.redirect('/register');
  }
});

// ---------- LOGIN PAGE ----------
router.get('/login', (req, res) => {
  const showError = req.query.error === '1';

  res.render('login', {
    title: 'Login',
    searchQuery: '',
    error: showError
  });
});

// ---------- HANDLE LOGIN ----------
router.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',    // go to Create page after login
    failureRedirect: '/login?error=1'
  })
);

// ---------- LOGOUT ----------
router.get('/logout', (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect('/login');
  });
});

module.exports = router;
