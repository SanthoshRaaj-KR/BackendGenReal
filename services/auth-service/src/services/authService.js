const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const emailService = require('./emailService');

class AuthService {

  // Generate a 6-digit OTP
  generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // Generate JWT access token
  generateTokens(user) {
    const payload = { 
      id: user._id, 
      email: user.email, 
      role: user.role,
      isVerified: user.isVerified 
    };
    
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    });
    
    return { accessToken };
  }

  // Register a new user
  async register(userData) {
    const existingUser = await User.findOne({ email: userData.email.toLowerCase() });
    if (existingUser) throw new Error('User already exists with this email');

    const userToCreate = {
      email: userData.email.toLowerCase(),
      password: userData.password,
      firstName: userData.firstName || 'User',
      lastName: userData.lastName || '',
      credits: 100,
      isActive: true,
      isVerified: true, // Auto-verify
      role: 'user'
    };

    const user = await User.create(userToCreate);

    const userResponse = user.toObject();
    delete userResponse.password;

    return userResponse;
  }

  // Login user with email/password
  async login(email, password, deviceInfo = {}) {
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) throw new Error('Invalid credentials');

    if (user.isLocked && user.isLocked()) {
      throw new Error('Account is temporarily locked. Please try again later.');
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 25) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 mins lock
      }
      await user.save();
      throw new Error('Invalid credentials');
    }

    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();

    const refreshToken = user.createRefreshToken(deviceInfo);
    await user.save();

    const { accessToken } = this.generateTokens(user);

    const userResponse = user.toObject();
    delete userResponse.password;

    return { user: userResponse, accessToken, refreshToken };
  }

  // Refresh access token
  async refreshToken(token) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      refreshToken: hashedToken,
      refreshTokenExpires: { $gt: Date.now() },
      isActive: true,
    });

    if (!user) throw new Error('Invalid or expired refresh token');

    const { accessToken } = this.generateTokens(user);
    const newRefreshToken = user.createRefreshToken(user.deviceInfo);
    await user.save();

    return { accessToken, refreshToken: newRefreshToken };
  }

  // Logout user
  async logout(refreshToken) {
    if (!refreshToken) return;
    try {
      const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const user = await User.findOne({ refreshToken: hashedToken });
      if (user) {
        user.clearRefreshToken();
        await user.save();
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  // Send OTP for password reset
  async sendPasswordResetOTP(email) {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return { success: true, message: 'If an account exists, OTP has been sent' };

    const otp = user.createPasswordResetOTP();
    await user.save();

    try {
      await emailService.sendOTPEmail(email, user.firstName, otp);
    } catch (error) {
      console.error('Failed to send OTP email:', error);
      throw new Error('Failed to send OTP. Please try again.');
    }

    return { success: true, message: 'OTP sent to your email address' };
  }

  // Verify OTP without deleting it (for frontend verification step)
  async verifyPasswordResetOTP(email, otp) {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) throw new Error('User not found');

    const validation = user.validatePasswordResetOTP(otp);
    
    if (!validation.valid) {
      await user.save(); // Save the updated attempt count
      throw new Error(validation.message);
    }

    return { success: true, message: validation.message };
  }

  // Reset password using verified OTP
  async resetPasswordWithOTP(email, otp, newPassword) {
    console.log('resetPasswordWithOTP called with:', { email, otp: otp ? '***' : null, newPassword: newPassword ? '***' : null });
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) throw new Error('User account not found.');

    console.log('User found, validating OTP...');

    const validation = user.validatePasswordResetOTP(otp);
    
    if (!validation.valid) {
      await user.save(); // Save the updated attempt count
      throw new Error(validation.message);
    }

    console.log('OTP validated, updating password...');

    // Update password and clear OTP data
    user.password = newPassword;
    user.clearPasswordResetOTP();
    user.clearRefreshToken(); // Clear all existing sessions
    await user.save();

    console.log('Password updated successfully');

    return { success: true, message: 'Password has been reset successfully. You can now log in with your new password.' };
  }

  // Register and immediately log in
  async registerAndLogin(userData, deviceInfo = {}) {
    const user = await this.register(userData);
    const { accessToken } = this.generateTokens(user);

    const foundUser = await User.findById(user._id);
    const refreshToken = foundUser.createRefreshToken(deviceInfo);
    foundUser.lastLogin = new Date();
    await foundUser.save();

    return { user, accessToken, refreshToken };
  }

  // Verify JWT token for middleware
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (!user || !user.isActive) throw new Error('User not found or inactive');
      return user;
    } catch {
      throw new Error('Invalid token');
    }
  }
}

module.exports = new AuthService();