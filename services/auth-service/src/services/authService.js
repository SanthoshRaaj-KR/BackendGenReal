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
    try {
      console.log('AuthService register called with:', userData); // Debug log
      
      const existingUser = await User.findOne({ email: userData.email.toLowerCase() });
      if (existingUser) {
        throw new Error('User already exists with this email');
      }

      // Ensure we have the required fields and add defaults
      const userToCreate = {
        email: userData.email.toLowerCase(),
        password: userData.password,
        firstName: userData.firstName || 'User',
        lastName: userData.lastName || '',
        credits: 100, // Give new users 100 free credits
        isActive: true,
        isVerified: false, // You can set to true for now if you don't want email verification
        role: 'user'
      };

      console.log('Creating user with data:', userToCreate); // Debug log

      const user = await User.create(userToCreate);
      console.log('User created successfully:', user._id); // Debug log

      // Generate verification token and send email (optional)
      try {
        const verificationToken = crypto.randomBytes(32).toString('hex');
        await redisClient.setex(`verify_${user._id}`, 86400, verificationToken);
        
        // Send verification email if emailService is available
        if (emailService && emailService.sendVerificationEmail) {
          await emailService.sendVerificationEmail(user.email, user.firstName, verificationToken);
        }
      } catch (emailError) {
        console.log('Email service not available or failed:', emailError.message);
        // Don't throw error here - user creation should still succeed
      }

      // Return the user without password
      const userResponse = user.toObject();
      delete userResponse.password;
      
      return userResponse;
    } catch (error) {
      console.error('AuthService register error:', error);
      throw error;
    }
  }

  async login(email, password, deviceInfo) {
    // Manually select password since it's excluded by default
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) throw new Error('Invalid credentials');

    if (user.isLocked && user.isLocked()) {
      throw new Error('Account is temporarily locked. Please try again later.');
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
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
    
    try {
      await this.saveRefreshToken(user._id, refreshToken, deviceInfo);
    } catch (refreshTokenError) {
      console.log('Failed to save refresh token:', refreshTokenError.message);
      // Continue without refresh token if there's an issue
    }

    // Return user without password
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return { user: userResponse, accessToken, refreshToken };
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
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return;

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await PasswordReset.create({ email: email.toLowerCase(), token: resetToken, expiresAt });
    
    try {
      if (emailService && emailService.sendPasswordResetEmail) {
        await emailService.sendPasswordResetEmail(email, user.firstName, resetToken);
      }
    } catch (emailError) {
      console.log('Failed to send password reset email:', emailError.message);
    }
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
    try {
      const storedToken = await redisClient.get(`verify_${userId}`);
      if (!storedToken || storedToken !== token) throw new Error('Invalid verification token');
      
      await User.updateOne({ _id: userId }, { isVerified: true });
      await redisClient.del(`verify_${userId}`);
    } catch (error) {
      console.error('Email verification error:', error);
      throw error;
    }
  }

  // New method to register and automatically generate tokens (for frontend auto-login)
  async registerAndLogin(userData, deviceInfo = null) {
    try {
      // Create the user
      const user = await this.register(userData);
      
      // Generate tokens for immediate login
      const { accessToken, refreshToken } = this.generateTokens(user);
      
      // Save refresh token if possible
      try {
        await this.saveRefreshToken(user._id, refreshToken, deviceInfo);
      } catch (refreshTokenError) {
        console.log('Failed to save refresh token during registration:', refreshTokenError.message);
      }

      return { 
        user, 
        accessToken, 
        refreshToken 
      };
    } catch (error) {
      throw error;
    }
  }
}

module.exports = new AuthService();