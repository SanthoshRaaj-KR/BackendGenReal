const authService = require('../services/authService');
const { getDeviceInfo } = require('../utils/helpers');

class AuthController {
  async register(req, res) {
    try {
      console.log('Register endpoint called with body:', req.body);
      
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
      const deviceInfo = getDeviceInfo(req);

      // Register and auto-login
      const result = await authService.registerAndLogin({
        email: email.toLowerCase().trim(),
        password,
        firstName: first.trim(),
        lastName: (last || '').trim(),
      }, deviceInfo);

      // Set refresh token as httpOnly cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful!',
        token: result.accessToken,
        user: {
          id: result.user._id,
          email: result.user.email,
          name: `${result.user.firstName} ${result.user.lastName}`.trim(),
          firstName: result.user.firstName,
          lastName: result.user.lastName,
          credits: result.user.credits || 100,
          role: result.user.role,
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
      console.log('Login endpoint called with body:', req.body);
      
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required',
        });
      }

      const deviceInfo = getDeviceInfo(req);
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
          role: result.user.role,
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

  async googleCallback(req, res) {
    try {
      const user = req.user;
      const deviceInfo = getDeviceInfo(req);
      
      if (!user) {
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
      }

      // Generate tokens
      const { accessToken } = authService.generateTokens(user);
      const refreshToken = user.createRefreshToken(deviceInfo);
      await user.save();

      // Set refresh token as httpOnly cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Redirect to frontend with success and token
      const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&user=${encodeURIComponent(JSON.stringify({
        id: user._id,
        email: user.email,
        name: `${user.firstName} ${user.lastName}`,
        role: user.role,
        isVerified: user.isVerified,
        profilePicture: user.profilePicture,
        credits: user.credits,
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
          code: 'NO_REFRESH_TOKEN'
        });
      }

      const tokens = await authService.refreshToken(refreshToken);
      
      // Set new refresh token
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
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
        code: 'INVALID_REFRESH_TOKEN'
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
      
      if (!email) {
        return res.status(400).json({
          success: false,
          message: 'Email is required',
        });
      }

      await authService.forgotPassword(email);
      
      res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.',
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
      
      if (!token || !password) {
        return res.status(400).json({
          success: false,
          message: 'Reset token and new password are required',
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 6 characters long',
        });
      }

      await authService.resetPassword(token, password);
      
      res.json({
        success: true,
        message: 'Password reset successful. Please log in with your new password.',
      });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(400).json({
        success: false,
        message: error.message || 'Password reset failed',
      });
    }
  }

  async verifyEmail(req, res) {
    try {
      const { token, userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({
          success: false,
          message: 'User ID is required',
        });
      }

      await authService.verifyEmail(token, userId);
      
      res.json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(400).json({
        success: false,
        message: error.message || 'Email verification failed',
      });
    }
  }

  async getProfile(req, res) {
    try {
      // req.user is set by authenticate middleware
      const user = req.user;
      
      res.json({
        success: true,
        data: {
          user: {
            id: user._id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            name: `${user.firstName} ${user.lastName}`.trim(),
            role: user.role,
            isVerified: user.isVerified,
            profilePicture: user.profilePicture,
            twoFactorEnabled: user.twoFactorEnabled,
            lastLogin: user.lastLogin,
            credits: user.credits,
            plan: user.plan,
            stats: user.getDashboardStats(),
          },
        },
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Error fetching profile',
      });
    }
  }

  // New method to get current user's credits
  async getCredits(req, res) {
    try {
      res.json({
        success: true,
        data: {
          credits: req.user.credits,
          totalCreditsUsed: req.user.totalCreditsUsed,
          plan: req.user.plan,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching credits',
      });
    }
  }

  // Method to deduct credits (called after successful analysis)
  async deductCredits(req, res) {
    try {
      const { amount = 1, analysisResult } = req.body;
      
      if (!req.user.hasEnoughCredits(amount)) {
        return res.status(402).json({
          success: false,
          message: 'Insufficient credits',
        });
      }

      // Record the analysis and deduct credits
      await req.user.recordAnalysis(analysisResult, amount);
      
      res.json({
        success: true,
        message: 'Credits deducted successfully',
        data: {
          remainingCredits: req.user.credits,
          totalAnalyses: req.user.analysesPerformed,
        },
      });
    } catch (error) {
      console.error('Credit deduction error:', error);
      res.status(500).json({
        success: false,
        message: 'Error deducting credits',
      });
    }
  }
}

module.exports = new AuthController();