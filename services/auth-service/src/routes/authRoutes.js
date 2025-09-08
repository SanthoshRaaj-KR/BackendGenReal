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
} = require('../middleware/Validation');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Increased for debugging
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

// Debug middleware to log all requests
const debugMiddleware = (req, res, next) => {
  console.log(`${req.method} ${req.path}`, {
    body: req.body,
    params: req.params,
    query: req.query
  });
  next();
};

// ============================================
// PUBLIC ROUTES (NO AUTHENTICATION REQUIRED)
// ============================================

// Email & Password Authentication
router.post('/register', generalLimiter, debugMiddleware, registerValidation, authController.register);
router.post('/login', authLimiter, debugMiddleware, loginValidation, authController.login);
router.post('/logout', generalLimiter, authController.logout);
router.post('/refresh-token', generalLimiter, authController.refreshToken);

// Password Reset with OTP
router.post('/send-password-reset-otp', authLimiter, debugMiddleware, otpValidation, authController.sendPasswordResetOTP);
router.post('/verify-password-reset-otp', authLimiter, debugMiddleware, verifyOtpValidation, authController.verifyPasswordResetOTP);
router.post('/reset-password-with-otp', authLimiter, debugMiddleware, resetPasswordWithOtpValidation, authController.resetPasswordWithOTP);

// ============================================
// GOOGLE OAUTH ROUTES - FIXED WITH REDIRECT HANDLING
// ============================================

// Google OAuth initiation - store redirect URL and frontend URL in session
router.get('/google', (req, res, next) => {
  // Store redirect parameters from query
  const redirectUrl = req.query.redirect || '/';
  const frontendUrl = req.query.frontend || process.env.FRONTEND_URL;
  
  // Store in session for callback
  req.session.oauthRedirect = redirectUrl;
  req.session.frontendUrl = frontendUrl;
  
  console.log('Google OAuth initiated with redirect:', redirectUrl, 'frontend:', frontendUrl);
  
  // Continue with Google authentication
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// Google OAuth callback - handle redirect with stored session data
router.get('/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=oauth_failed`,
    session: false 
  }),
  (req, res) => {
    try {
      const user = req.user;
      if (!user) {
        const redirectUrl = req.session?.oauthRedirect || '/';
        const frontendUrl = req.session?.frontendUrl || process.env.FRONTEND_URL;
        return res.redirect(`${frontendUrl}/login?error=oauth_failed&redirect=${encodeURIComponent(redirectUrl)}`);
      }

      // Generate tokens (you'll need to implement this in authController)
      const deviceInfo = require('../utils/helpers').getDeviceInfo(req);
      const authService = require('../services/authService');
      const { accessToken } = authService.generateTokens(user);
      const refreshToken = user.createRefreshToken(deviceInfo);
      
      // Save refresh token
      user.save();

      // Set refresh token cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Get stored redirect information
      const redirectUrl = req.session?.oauthRedirect || '/';
      const frontendUrl = req.session?.frontendUrl || process.env.FRONTEND_URL;
      
      // Clear session data
      if (req.session?.oauthRedirect) delete req.session.oauthRedirect;
      if (req.session?.frontendUrl) delete req.session.frontendUrl;

      // Redirect with all parameters
      const callbackUrl = `${frontendUrl}/auth/callback?token=${accessToken}&userId=${user._id}&redirect=${encodeURIComponent(redirectUrl)}`;
      
      console.log('Google OAuth success, redirecting to:', callbackUrl);
      res.redirect(callbackUrl);
      
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      const redirectUrl = req.session?.oauthRedirect || '/';
      const frontendUrl = req.session?.frontendUrl || process.env.FRONTEND_URL;
      res.redirect(`${frontendUrl}/login?error=oauth_error&redirect=${encodeURIComponent(redirectUrl)}`);
    }
  }
);

// ============================================
// PROTECTED ROUTES (AUTHENTICATION REQUIRED)
// ============================================

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

// Get user profile
router.get('/profile', authenticate, authController.getProfile);

// ============================================
// TEST/DEBUG ROUTES
// ============================================

// Test endpoint for debugging
router.post('/test', debugMiddleware, (req, res) => {
  res.json({
    success: true,
    message: 'Test endpoint working',
    receivedData: req.body,
    headers: req.headers,
    timestamp: new Date().toISOString()
  });
});

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is healthy',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV
  });
});

module.exports = router;