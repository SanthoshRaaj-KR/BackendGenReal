const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const {
  registerValidation,
  loginValidation,
  otpValidation,
  verifyOtpValidation,
  resetPasswordWithOtpValidation
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

// Password Reset with OTP
router.post('/send-password-reset-otp', authLimiter, otpValidation, authController.sendPasswordResetOTP);
router.post('/verify-password-reset-otp', authLimiter, verifyOtpValidation, authController.verifyPasswordResetOTP);
router.post('/reset-password-with-otp', authLimiter, resetPasswordWithOtpValidation, authController.resetPasswordWithOTP);


// Google OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  authController.googleCallback
);


// Validate token endpoint (useful for frontend and other services)
router.get('/validate', authenticate, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    user: {
      id: req.user._id,
      email: req.user.email,
      name: req.user.fullName,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      role: req.user.role,
      credits: req.user.credits,
      isVerified: req.user.isVerified,
      plan: req.user.plan
    }
  });
});

module.exports = router;