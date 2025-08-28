const authService = require('../services/authService');
const { getDeviceInfo } = require('../utils/helpers');
const jwt = require('jsonwebtoken');

class AuthController {
    async register(req, res) {
    try {
      console.log('Register endpoint called with body:', req.body); // Debug log
      
      const { email, password, firstName, lastName, name } = req.body;
      
      // Handle both 'name' (from frontend) and separate firstName/lastName
      let first = firstName;
      let last = lastName;
      
      if (name && !firstName && !lastName) {
        const nameParts = name.trim().split(' ');
        first = nameParts[0];
        last = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';
      }

      // Validate required fields
      if (!first || !email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Name, email, and password are required',
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 6 characters long',
        });
      }

      // Get device info for refresh token
      const deviceInfo = {
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
      };

      // Use the new registerAndLogin method for immediate login after registration
      const result = await authService.registerAndLogin({
        email: email.toLowerCase().trim(),
        password,
        firstName: first.trim(),
        lastName: (last || '').trim(),
      }, deviceInfo);

      // Set refresh token as httpOnly cookie (more secure)
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful!',
        token: result.accessToken, // This is what your frontend expects
        user: {
          id: result.user._id,
          email: result.user.email,
          name: `${result.user.firstName} ${result.user.lastName}`.trim(),
          firstName: result.user.firstName,
          lastName: result.user.lastName,
          credits: result.user.credits || 100,
        },
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(400).json({
        success: false,
        message: error.message || 'Registration failed',
      });
    }
  }

  async login(req, res) {
    try {
      console.log('Login endpoint called with body:', req.body); // Debug log
      
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required',
        });
      }

      const deviceInfo = {
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
      };

      const result = await authService.login(email, password, deviceInfo);

      // Set refresh token as httpOnly cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({
        success: true,
        message: 'Login successful!',
        token: result.accessToken,
        user: {
          id: result.user._id,
          email: result.user.email,
          name: `${result.user.firstName} ${result.user.lastName}`.trim(),
          firstName: result.user.firstName,
          lastName: result.user.lastName,
          credits: result.user.credits || 0,
        },
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(400).json({
        success: false,
        message: error.message || 'Login failed',
      });
    }
  }

  // NEW: Google OAuth callback handler
  async googleCallback(req, res) {
    try {
      const user = req.user; // Set by Passport after successful authentication
      const deviceInfo = getDeviceInfo(req);
      
      if (!user) {
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
      }

      // Generate tokens for the authenticated user
      const tokens = authService.generateTokens(user);
      await authService.saveRefreshToken(user._id, tokens.refreshToken, deviceInfo);

      // Set refresh token as httpOnly cookie
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Redirect to frontend with success and token
      const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${tokens.accessToken}&user=${encodeURIComponent(JSON.stringify({
        id: user._id,
        email: user.email,
        name: `${user.firstName} ${user.lastName}`,
        role: user.role,
        isVerified: user.isVerified,
        profilePicture: user.profilePicture,
      }))}`;

      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Google callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_error`);
    }
  }

  async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: 'Refresh token not found',
        });
      }

      const tokens = await authService.refreshToken(refreshToken);
      
      // Set new refresh token
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({
        success: true,
        token: tokens.accessToken,
      });
    } catch (error) {
      console.error('Refresh token error:', error);
      res.status(401).json({
        success: false,
        message: error.message,
      });
    }
  }
  async logout(req, res) {
      try {
        const refreshToken = req.cookies.refreshToken;
        await authService.logout(refreshToken);
        
        res.clearCookie('refreshToken');
        res.json({
          success: true,
          message: 'Logout successful',
        });
      } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
          success: false,
          message: 'Logout failed',
        });
      }
    }

    async forgotPassword(req, res) {
      try {
        const { email } = req.body;
        await authService.forgotPassword(email);
        
        res.json({
          success: true,
          message: 'Password reset email sent if account exists',
        });
      } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
          success: false,
          message: 'Failed to process password reset request',
        });
      }
    }

  async resetPassword(req, res) {
    try {
      const { token, password } = req.body;
      await authService.resetPassword(token, password);
      
      res.json({
        success: true,
        message: 'Password reset successful',
      });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  }

  async verifyEmail(req, res) {
      try {
        const { token, userId } = req.body;
        await authService.verifyEmail(token, userId);
        
        res.json({
          success: true,
          message: 'Email verified successfully',
        });
      } catch (error) {
        console.error('Email verification error:', error);
        res.status(400).json({
          success: false,
          message: error.message,
        });
      }
    }

  async getProfile(req, res) {
    try {
      res.json({
        success: true,
        data: {
          user: {
            id: req.user._id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            name: `${req.user.firstName} ${req.user.lastName}`,
            role: req.user.role,
            isVerified: req.user.isVerified,
            profilePicture: req.user.profilePicture,
            twoFactorEnabled: req.user.twoFactorEnabled,
            lastLogin: req.user.lastLogin,
          },
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching profile',
      });
    }
  }
}

module.exports = new AuthController();