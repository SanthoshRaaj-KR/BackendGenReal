const authService = require('../services/authService');
const { getDeviceInfo } = require('../utils/helpers');

class AuthController {
  async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;
      
      const user = await authService.register({
        email,
        password,
        firstName,
        lastName,
      });

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email for verification.',
        data: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const deviceInfo = getDeviceInfo(req);

      const result = await authService.login(email, password, deviceInfo);

      // Set refresh token as httpOnly cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            firstName: result.user.firstName,
            lastName: result.user.lastName,
            role: result.user.role,
            isVerified: result.user.isVerified,
            profilePicture: result.user.profilePicture,
          },
          accessToken: result.accessToken,
        },
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error.message,
      });
    }
  }

  async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: 'Refresh token not provided',
        });
      }

      const tokens = await authService.refreshToken(refreshToken);

      // Set new refresh token as httpOnly cookie
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        success: true,
        data: {
          accessToken: tokens.accessToken,
        },
      });
    } catch (error) {
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
      res.status(500).json({
        success: false,
        message: 'Error during logout',
      });
    }
  }

  async forgotPassword(req, res) {
    try {
      const { email } = req.body;
      
      await authService.forgotPassword(email);

      res.json({
        success: true,
        message: 'If an account with that email exists, we\'ve sent a password reset link.',
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error sending password reset email',
      });
    }
  }

  async resetPassword(req, res) {
    try {
      const { token, password } = req.body;
      
      await authService.resetPassword(token, password);

      res.json({
        success: true,
        message: 'Password reset successful. Please login with your new password.',
      });
    } catch (error) {
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
            id: req.user.id,
            email: req.user.email,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
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