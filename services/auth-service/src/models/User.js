const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email',
    ],
  },
  password: {
    type: String,
    required: function() { return !this.googleId; },
    minlength: [6, 'Password must be at least 6 characters long'],
    select: false, // Don't send password back in queries by default
  },
  firstName: {
    type: String,
    required: [true, 'Please provide a first name'],
    trim: true,
  },
  lastName: {
    type: String,
    required: false,
    trim: true,
    default: '',
  },
  role: {
    type: String,
    enum: ['admin', 'user', 'premium_user'],
    default: 'user',
  },
  isVerified: {
    type: Boolean,
    default: true, // Set to true by default since we're not using email verification for now
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  lastLogin: {
    type: Date,
  },
  profilePicture: {
    type: String,
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false,
  },
  loginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: {
    type: Date,
  },
  // Credits system
  credits: {
    type: Number,
    default: 100,
    min: [0, 'Credits cannot be negative'],
  },
  totalCreditsUsed: {
    type: Number,
    default: 0,
  },
  plan: {
    type: String,
    enum: ['free', 'basic', 'premium', 'enterprise'],
    default: 'free',
  },
  // Analytics fields
  analysesPerformed: {
    type: Number,
    default: 0,
  },
  authenticResults: {
    type: Number,
    default: 0,
  },
  suspiciousResults: {
    type: Number,
    default: 0,
  },
  // Refresh token fields (embedded in user document)
  refreshToken: {
    type: String,
    default: null,
  },
  refreshTokenExpires: {
    type: Date,
    default: null,
  },
  deviceInfo: {
    userAgent: String,
    ip: String,
    lastUsed: Date,
  },
  // OTP fields for password reset
  passwordResetOTP: {
    type: String,
    default: null,
  },
  passwordResetOTPExpires: {
    type: Date,
    default: null,
  },
  passwordResetOTPAttempts: {
    type: Number,
    default: 0,
  },
  passwordResetOTPAttemptsExpires: {
    type: Date,
    default: null,
  },
}, {
  timestamps: true,
});

// Indexes for performance
UserSchema.index({ passwordResetToken: 1 });
UserSchema.index({ refreshToken: 1 });
UserSchema.index({ passwordResetOTP: 1 });

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password method
UserSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

// Check if account is locked
UserSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Generate refresh token
UserSchema.methods.createRefreshToken = function(deviceInfo = {}) {
  const refreshToken = crypto.randomBytes(64).toString('hex');
  
  this.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  this.refreshTokenExpires = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
  this.deviceInfo = {
    ...deviceInfo,
    lastUsed: new Date(),
  };
  
  return refreshToken; // Return the unhashed token
};

// Validate refresh token
UserSchema.methods.validateRefreshToken = function(candidateToken) {
  if (!this.refreshToken || !this.refreshTokenExpires) return false;
  if (Date.now() > this.refreshTokenExpires) return false;
  
  const hashedCandidate = crypto.createHash('sha256').update(candidateToken).digest('hex');
  return this.refreshToken === hashedCandidate;
};

// Clear refresh token
UserSchema.methods.clearRefreshToken = function() {
  this.refreshToken = null;
  this.refreshTokenExpires = null;
  this.deviceInfo = {};
};

// OTP methods
UserSchema.methods.createPasswordResetOTP = function() {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  this.passwordResetOTP = otp;
  this.passwordResetOTPExpires = Date.now() + 3 * 60 * 1000; // 3 minutes
  this.passwordResetOTPAttempts = 0;
  this.passwordResetOTPAttemptsExpires = Date.now() + 3 * 60 * 1000; // 3 minutes
  
  return otp;
};

UserSchema.methods.validatePasswordResetOTP = function(candidateOTP) {
  if (!this.passwordResetOTP || !this.passwordResetOTPExpires) {
    return { valid: false, message: 'OTP has expired or is invalid. Please request a new one.' };
  }
  
  if (Date.now() > this.passwordResetOTPExpires) {
    return { valid: false, message: 'OTP has expired. Please request a new one.' };
  }
  
  // Check if attempts have expired (reset counter if expired)
  if (this.passwordResetOTPAttemptsExpires && Date.now() > this.passwordResetOTPAttemptsExpires) {
    this.passwordResetOTPAttempts = 0;
    this.passwordResetOTPAttemptsExpires = Date.now() + 3 * 60 * 1000;
  }
  
  if (this.passwordResetOTPAttempts >= 3) {
    return { valid: false, message: 'Too many invalid attempts. Please request a new OTP.' };
  }
  
  if (this.passwordResetOTP !== candidateOTP) {
    this.passwordResetOTPAttempts += 1;
    const remainingAttempts = 3 - this.passwordResetOTPAttempts;
    return { valid: false, message: `Invalid OTP. ${remainingAttempts} attempts remaining.` };
  }
  
  return { valid: true, message: 'OTP verified successfully' };
};

UserSchema.methods.clearPasswordResetOTP = function() {
  this.passwordResetOTP = null;
  this.passwordResetOTPExpires = null;
  this.passwordResetOTPAttempts = 0;
  this.passwordResetOTPAttemptsExpires = null;
};

// Credits management methods
UserSchema.methods.deductCredits = function(amount) {
  if (this.credits >= amount) {
    this.credits -= amount;
    this.totalCreditsUsed += amount;
    return true;
  }
  return false;
};

UserSchema.methods.addCredits = function(amount) {
  this.credits += amount;
  return this.credits;
};

UserSchema.methods.hasEnoughCredits = function(amount) {
  return this.credits >= amount;
};

// Record analysis method
UserSchema.methods.recordAnalysis = function(result, creditsUsed = 1) {
  this.analysesPerformed += 1;
  this.deductCredits(creditsUsed);
  
  if (result && result.toLowerCase().includes('authentic')) {
    this.authenticResults += 1;
  } else if (result && (result.toLowerCase().includes('suspicious') || result.toLowerCase().includes('fake'))) {
    this.suspiciousResults += 1;
  }
  
  return this.save();
};

// Virtual for full name
UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`.trim();
});

// Get dashboard stats
UserSchema.methods.getDashboardStats = function() {
  return {
    totalAnalyses: this.analysesPerformed,
    authenticContent: this.authenticResults,
    suspiciousContent: this.suspiciousResults,
    averageConfidence: 85.7, // You can calculate this based on your analysis records
    credits: {
      total: this.credits + this.totalCreditsUsed,
      used: this.totalCreditsUsed,
      remaining: this.credits
    }
  };
};

// Ensure virtual fields are serialized
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('User', UserSchema);