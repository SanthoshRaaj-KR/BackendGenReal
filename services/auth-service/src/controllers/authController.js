const authService = require('../services/authService');
const { getDeviceInfo } = require('../utils/helpers');
const { logActivity } = require('../utils/loger');

class AuthController {
  // ================== REGISTER ==================
  async register(req, res) {
    try {
      const { email, password, firstName, lastName, name } = req.body;
      let first = firstName;
      let last = lastName;

      if (name && !firstName && !lastName) {
        const parts = name.trim().split(' ');
        first = parts[0];
        last = parts.length > 1 ? parts.slice(1).join(' ') : '';
      }

      if (!first || !email || !password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Invalid registration data' });
      }

      const deviceInfo = getDeviceInfo(req);
      const result = await authService.registerAndLogin({
        email: email.toLowerCase().trim(),
        password,
        firstName: first.trim(),
        lastName: (last || '').trim(),
      }, deviceInfo);

      // Set refresh token in HttpOnly cookie
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Return access token + minimal user info
      res.status(201).json({
        success: true,
        token: result.accessToken,
        user: {
          id: result.user._id,
          email: result.user.email,
          name: `${result.user.firstName} ${result.user.lastName}`.trim(),
          role: result.user.role,
          credits: result.user.credits || 100,
          isVerified: result.user.isVerified,
        },
      });
    } catch (err) {
      res.status(400).json({ success: false, message: err.message || 'Registration failed' });
    }
  }

  // ================== LOGIN ==================
  async login(req, res) {
    try {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

      const deviceInfo = getDeviceInfo(req);
      const result = await authService.login(email, password, deviceInfo);

      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        success: true,
        token: result.accessToken,
        user: {
          id: result.user._id,
          email: result.user.email,
          name: `${result.user.firstName} ${result.user.lastName}`.trim(),
          role: result.user.role,
          credits: result.user.credits,
          isVerified: result.user.isVerified,
        },
      });
    } catch (err) {
      res.status(400).json({ success: false, message: err.message || 'Login failed' });
    }
  }

  // ================== GOOGLE CALLBACK - FIXED ==================
  async googleCallback(req, res) {
    try {
      const user = req.user;
      if (!user) {
        // Get redirect URL from session or fallback to default
        const redirectUrl = req.session?.oauthRedirect || '/';
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed&redirect=${encodeURIComponent(redirectUrl)}`);
      }

      const deviceInfo = getDeviceInfo(req);
      const { accessToken } = authService.generateTokens(user);
      const refreshToken = user.createRefreshToken(deviceInfo);
      await user.save();

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Get the original redirect URL from session (stored during OAuth initiation)
      const redirectUrl = req.session?.oauthRedirect || '/';
      
      // Clear the redirect from session
      if (req.session?.oauthRedirect) {
        delete req.session.oauthRedirect;
      }

      // Redirect with token, userId, and the original redirect parameter
      const callbackUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&userId=${user._id}&redirect=${encodeURIComponent(redirectUrl)}`;
      
      console.log('Google OAuth callback redirect URL:', callbackUrl); // Debug log
      res.redirect(callbackUrl);
    } catch (error) {
      console.error('Google OAuth error:', error);
      const redirectUrl = req.session?.oauthRedirect || '/';
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_error&redirect=${encodeURIComponent(redirectUrl)}`);
    }
  }

  // ================== GOOGLE OAUTH INITIATION - NEW METHOD ==================
  async googleOAuth(req, res, next) {
    try {
      // Store the redirect URL in session before initiating OAuth
      const redirectUrl = req.query.redirect || '/';
      req.session.oauthRedirect = redirectUrl;
      
      // Continue with passport Google authentication
      next();
    } catch (error) {
      console.error('Google OAuth initiation error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_error`);
    }
  }

  // ================== REFRESH TOKEN ==================
  async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) return res.status(401).json({ success: false, message: 'No refresh token' });

      const tokens = await authService.refreshToken(refreshToken);

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ success: true, token: tokens.accessToken });
    } catch (err) {
      res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
  }

  // ================== LOGOUT ==================
  async logout(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      await authService.logout(refreshToken);
      res.clearCookie('refreshToken');
      res.json({ success: true, message: 'Logged out' });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ success: false, message: 'Logout failed' });
    }
  }

  // ================== VALIDATE TOKEN ==================
  async validate(req, res) {
    try {
      const user = req.user;
      res.json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          name: `${user.firstName} ${user.lastName}`.trim(),
          role: user.role,
          credits: user.credits,
          isVerified: user.isVerified,
          profilePicture: user.profilePicture,
        },
      });
    } catch (error) {
      console.error('Validate token error:', error);
      res.status(500).json({ success: false, message: 'Token validation failed' });
    }
  }

  // ================== PASSWORD RESET / OTP ==================
  async sendPasswordResetOTP(req, res) {
    try {
      const { email } = req.body;
      if (!email) return res.status(400).json({ success: false, message: 'Email required' });

      const result = await authService.sendPasswordResetOTP(email.toLowerCase().trim());
      res.json(result);
    } catch (err) {
      console.error('Send OTP error:', err);
      res.status(500).json({ success: false, message: err.message || 'Failed to send OTP' });
    }
  }

  async verifyPasswordResetOTP(req, res) {
    try {
      const { email, otp } = req.body;
      if (!email || !otp) return res.status(400).json({ success: false, message: 'Email and OTP required' });

      const result = await authService.verifyPasswordResetOTP(email.toLowerCase().trim(), otp.trim());
      res.json(result);
    } catch (err) {
      console.error('Verify OTP error:', err);
      res.status(400).json({ success: false, message: err.message || 'Invalid OTP' });
    }
  }

  async resetPasswordWithOTP(req, res) {
    try {
      console.log('Reset password request body:', req.body); // Debug log
      const { email, otp, newPassword } = req.body;
      
      if (!email || !otp || !newPassword) {
        console.log('Missing required fields:', { email: !!email, otp: !!otp, newPassword: !!newPassword });
        return res.status(400).json({ 
          success: false, 
          message: 'Email, OTP, and new password are required' 
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ 
          success: false, 
          message: 'Password must be at least 6 characters long' 
        });
      }

      const result = await authService.resetPasswordWithOTP(
        email.toLowerCase().trim(), 
        otp.toString().trim(), 
        newPassword
      );
      
      res.json(result);
    } catch (err) {
      console.error('Reset password error:', err);
      res.status(400).json({ success: false, message: err.message || 'Failed to reset password' });
    }
  }

  // ================== GET PROFILE ==================
  async getProfile(req, res) {
    try {
      const user = req.user;
      res.json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          name: `${user.firstName} ${user.lastName}`.trim(),
          role: user.role,
          credits: user.credits,
          isVerified: user.isVerified,
          profilePicture: user.profilePicture,
        },
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({ success: false, message: 'Error fetching profile' });
    }
  }
}

module.exports = new AuthController();