const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const {
  registerValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
} = require('../middleware/validation');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    success: false,
    message: 'Too many requests, please try again later.',
  },
});

// ============================================
// PUBLIC ROUTES (NO AUTHENTICATION REQUIRED)
// ============================================

// Email & Password Authentication
router.post('/register', generalLimiter, registerValidation, authController.register);
router.post('/login', authLimiter, loginValidation, authController.login);
router.post('/logout', generalLimiter, authController.logout);
router.post('/refresh-token', generalLimiter, authController.refreshToken);

// Password Reset (public routes)
router.post('/forgot-password', authLimiter, forgotPasswordValidation, authController.forgotPassword);
router.post('/reset-password', authLimiter, resetPasswordValidation, authController.resetPassword);

// Email Verification (public route)
router.post('/verify-email', generalLimiter, authController.verifyEmail);

// Google OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  authController.googleCallback
);

// ============================================
// PROTECTED ROUTES (AUTHENTICATION REQUIRED)
// ============================================

// Get user profile
router.get('/profile', authenticate, authController.getProfile);

// Get user credits
router.get('/credits', authenticate, authController.getCredits);

// Deduct credits (called after successful analysis)
router.post('/deduct-credits', authenticate, authController.deductCredits);

// Validate token endpoint (useful for frontend to check if token is still valid)
router.get('/validate', authenticate, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    user: {
      id: req.user._id,
      email: req.user.email,
      name: req.user.fullName,
      role: req.user.role,
      credits: req.user.credits,
    }
  });
});

module.exports = router;