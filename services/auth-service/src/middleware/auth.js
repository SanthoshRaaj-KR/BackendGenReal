// services/auth-service/src/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authService = require('../services/authService');

/**
 * Main authentication middleware
 * Protects routes by verifying JWT token
 */
const authenticate = async (req, res, next) => {
  try {
    let token;
    
    // Check for token in Authorization header (Bearer token)
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // Alternative: Check for token in cookies (if you're using cookie-based auth)
    else if (req.cookies && req.cookies.authToken) {
      token = req.cookies.authToken;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required. Please log in.',
        code: 'NO_TOKEN'
      });
    }

    // Verify the token and get user
    const user = await authService.verifyToken(token);
    
    // Check if user account is active
    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Check if user is verified (optional - you can remove this if not needed)
    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email address',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // Attach user to request object for use in route handlers
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please log in again.',
        code: 'INVALID_TOKEN'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please log in again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    return res.status(500).json({
      success: false,
      message: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Authorization middleware for role-based access control
 * Usage: authorize('admin', 'premium_user')
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'NOT_AUTHENTICATED'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        requiredRoles: roles,
        userRole: req.user.role
      });
    }
    
    next();
  };
};

/**
 * Credit-based access control
 * Checks if user has enough credits for the operation
 */
const requireCredits = (requiredCredits = 1) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'NOT_AUTHENTICATED'
      });
    }

    if (!req.user.hasEnoughCredits(requiredCredits)) {
      return res.status(402).json({
        success: false,
        message: `Insufficient credits. Required: ${requiredCredits}, Available: ${req.user.credits}`,
        code: 'INSUFFICIENT_CREDITS',
        requiredCredits,
        availableCredits: req.user.credits
      });
    }

    // Store required credits in req for later deduction
    req.requiredCredits = requiredCredits;
    next();
  };
};

/**
 * Optional authentication - doesn't fail if no token provided
 * Useful for routes that work for both authenticated and unauthenticated users
 */
const optionalAuth = async (req, res, next) => {
  try {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.authToken) {
      token = req.cookies.authToken;
    }

    if (token) {
      try {
        const user = await authService.verifyToken(token);
        if (user && user.isActive) {
          req.user = user;
        }
      } catch (error) {
        // Token is invalid but we don't fail the request
        console.log('Optional auth failed:', error.message);
      }
    }

    next();
  } catch (error) {
    // Don't fail the request even if there's an error
    next();
  }
};

/**
 * Admin-only middleware
 */
const adminOnly = [authenticate, authorize('admin')];

/**
 * Premium user middleware
 */
const premiumOnly = [authenticate, authorize('premium_user', 'admin')];

module.exports = { 
  authenticate, 
  authorize, 
  requireCredits,
  optionalAuth,
  adminOnly,
  premiumOnly
};