const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const PasswordReset = require('../models/PasswordReset');
const emailService = require('./emailService');
const redisClient = require('../config/redis');

class AuthService {
  generateTokens(user) {
    const payload = { id: user._id, email: user.email, role: user.role };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    });
    return { accessToken, refreshToken };
  }

  async saveRefreshToken(userId, refreshToken, deviceInfo) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    await RefreshToken.create({ token: refreshToken, userId, expiresAt, deviceInfo });
  }

  async register(userData) {
    const existingUser = await User.findOne({ email: userData.email });
    if (existingUser) throw new Error('User already exists with this email');

    const user = await User.create(userData);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    await redisClient.setex(`verify_${user._id}`, 86400, verificationToken);
    await emailService.sendVerificationEmail(user.email, user.firstName, verificationToken);
    return user;
  }

  async login(email, password, deviceInfo) {
    // Manually select password since it's excluded by default
    const user = await User.findOne({ email }).select('+password');
    if (!user) throw new Error('Invalid credentials');

    if (user.isLocked()) throw new Error('Account is temporarily locked. Please try again later.');

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
      }
      await user.save();
      throw new Error('Invalid credentials');
    }

    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();
    await user.save();

    const { accessToken, refreshToken } = this.generateTokens(user);
    await this.saveRefreshToken(user._id, refreshToken, deviceInfo);
    return { user, accessToken, refreshToken };
  }

  async refreshToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
      const tokenRecord = await RefreshToken.findOne({ token, isRevoked: false });
      if (!tokenRecord) throw new Error('Invalid refresh token');

      const user = await User.findById(decoded.id);
      if (!user || !user.isActive) throw new Error('User not found or inactive');

      const tokens = this.generateTokens(user);
      
      tokenRecord.isRevoked = true;
      await tokenRecord.save();
      
      await this.saveRefreshToken(user._id, tokens.refreshToken, tokenRecord.deviceInfo);
      return tokens;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  async logout(refreshToken) {
    if (refreshToken) {
      await RefreshToken.updateOne({ token: refreshToken }, { isRevoked: true });
    }
  }

  async forgotPassword(email) {
    const user = await User.findOne({ email });
    if (!user) return;

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await PasswordReset.create({ email, token: resetToken, expiresAt });
    await emailService.sendPasswordResetEmail(email, user.firstName, resetToken);
  }

  async resetPassword(token, newPassword) {
    const resetRecord = await PasswordReset.findOne({
      token,
      isUsed: false,
      expiresAt: { $gt: new Date() }, // Mongoose syntax for 'greater than'
    });
    if (!resetRecord) throw new Error('Invalid or expired reset token');

    const user = await User.findOne({ email: resetRecord.email });
    if (!user) throw new Error('User not found');

    user.password = newPassword;
    await user.save();
    
    resetRecord.isUsed = true;
    await resetRecord.save();

    await RefreshToken.updateMany({ userId: user._id }, { isRevoked: true });
  }

  async verifyEmail(token, userId) {
    const storedToken = await redisClient.get(`verify_${userId}`);
    if (!storedToken || storedToken !== token) throw new Error('Invalid verification token');
    
    await User.updateOne({ _id: userId }, { isVerified: true });
    await redisClient.del(`verify_${userId}`);
  }
}

module.exports = new AuthService();