const express = require('express');
const passport = require('passport'); // ✅ Import Passport
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const {
  registerValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
} = require('../middleware/validation'); // Corrected filename case
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: 'Too many requests, please try again later.',
  },
});

// --- Email & Password Routes ---
router.post('/register', generalLimiter, registerValidation, authController.register);
router.post('/login', authLimiter, loginValidation, authController.login);
router.post('/logout', generalLimiter, authController.logout);
router.post('/refresh-token', generalLimiter, authController.refreshToken);
router.post('/forgot-password', authLimiter, forgotPasswordValidation, authController.forgotPassword);
router.post('/reset-password', authLimiter, resetPasswordValidation, authController.resetPassword);
router.post('/verify-email', generalLimiter, authController.verifyEmail);
router.get('/profile', authenticate, authController.getProfile);


// ==================================================
// ✅ ADD THESE MISSING GOOGLE OAUTH ROUTES
// ==================================================

// @desc    Auth with Google (starts the process)
// @route   GET /api/auth/google
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// @desc    Google auth callback (where Google redirects back to)
// @route   GET /api/auth/google/callback
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  authController.googleCallback
);


module.exports = router;