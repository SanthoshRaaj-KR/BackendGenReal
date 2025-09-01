const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const emailService = require('./emailService');

class AuthService {
  generateTokens(user) {
    const payload = { 
      id: user._id, 
      email: user.email, 
      role: user.role,
      isVerified: user.isVerified 
    };
    
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h', // Increased from 15m to 1h for better UX
    });
    
    return { accessToken };
  }

  async register(userData) {
    try {
      console.log('AuthService register called with:', userData);
      
      const existingUser = await User.findOne({ email: userData.email.toLowerCase() });
      if (existingUser) {
        throw new Error('User already exists with this email');
      }

      const userToCreate = {
        email: userData.email.toLowerCase(),
        password: userData.password,
        firstName: userData.firstName || 'User',
        lastName: userData.lastName || '',
        credits: 100,
        isActive: true,
        isVerified: true, // Auto-verify for simplicity
        role: 'user'
      };

      console.log('Creating user with data:', userToCreate);

      const user = await User.create(userToCreate);
      console.log('User created successfully:', user._id);

      // Return the user without password
      const userResponse = user.toObject();
      delete userResponse.password;
      
      return userResponse;
    } catch (error) {
      console.error('AuthService register error:', error);
      throw error;
    }
  }

  async login(email, password, deviceInfo = {}) {
    // Find user and include password for comparison
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) throw new Error('Invalid credentials');

    // Check if account is locked
    if (user.isLocked && user.isLocked()) {
      throw new Error('Account is temporarily locked. Please try again later.');
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      }
      await user.save();
      throw new Error('Invalid credentials');
    }

    // Reset login attempts and update last login
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();

    // Generate and store refresh token
    const refreshToken = user.createRefreshToken(deviceInfo);
    await user.save();

    // Generate access token
    const { accessToken } = this.generateTokens(user);

    // Return user without password
    const userResponse = user.toObject();
    delete userResponse.password;
    
    return { user: userResponse, accessToken, refreshToken };
  }

  async refreshToken(token) {
    try {
      // Find user with this refresh token
      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
      const user = await User.findOne({
        refreshToken: hashedToken,
        refreshTokenExpires: { $gt: Date.now() },
        isActive: true,
      });

      if (!user) {
        throw new Error('Invalid or expired refresh token');
      }

      // Generate new tokens
      const { accessToken } = this.generateTokens(user);
      const newRefreshToken = user.createRefreshToken(user.deviceInfo);
      await user.save();

      return { accessToken, refreshToken: newRefreshToken };
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  async logout(refreshToken) {
    if (refreshToken) {
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
  }

  async forgotPassword(email) {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Don't reveal if email exists - security best practice
      return;
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save();
    
    try {
      if (emailService && emailService.sendPasswordResetEmail) {
        await emailService.sendPasswordResetEmail(email, user.firstName, resetToken);
      }
    } catch (emailError) {
      console.log('Failed to send password reset email:', emailError.message);
      // Clear the reset token if email fails
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      await user.save();
      throw new Error('Failed to send reset email');
    }
  }

  async resetPassword(token, newPassword) {
    // Hash the token to compare with stored hashed version
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    }).select('+password');

    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    // Set new password (will be hashed by pre-save middleware)
    user.password = newPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    
    // Clear all refresh tokens for security
    user.clearRefreshToken();
    
    await user.save();
  }

  async verifyEmail(token, userId) {
    try {
      // Simple verification - just mark as verified
      const user = await User.findByIdAndUpdate(userId, { isVerified: true }, { new: true });
      if (!user) {
        throw new Error('User not found');
      }
      return user;
    } catch (error) {
      console.error('Email verification error:', error);
      throw error;
    }
  }

  // Register and automatically log in
  async registerAndLogin(userData, deviceInfo = {}) {
    try {
      // Create the user
      const user = await this.register(userData);
      
      // Generate tokens for immediate login
      const { accessToken } = this.generateTokens(user);
      
      // Generate and save refresh token
      const refreshToken = await User.findById(user._id).then(foundUser => {
        const token = foundUser.createRefreshToken(deviceInfo);
        foundUser.lastLogin = new Date();
        return foundUser.save().then(() => token);
      });

      return { 
        user, 
        accessToken, 
        refreshToken 
      };
    } catch (error) {
      throw error;
    }
  }

  // Verify JWT token (for middleware)
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      return user;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
}

module.exports = new AuthService();