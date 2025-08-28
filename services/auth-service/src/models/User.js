
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email',
    ],
  },
  password: {
    type: String,
    // Required is a function to allow null for OAuth users
    required: function() { return !this.googleId; },
    minlength: 8,
    select: false, // Don't send password back in queries by default
  },
  firstName: {
    type: String,
    required: [true, 'Please provide a first name'],
  },
  lastName: {
    type: String,
    required: [true, 'Please provide a last name'],
  },
  role: {
    type: String,
    enum: ['admin', 'user', 'premium_user'],
    default: 'user',
  },
  isVerified: {
    type: Boolean,
    default: false,
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
    sparse: true, // Allows multiple null values for non-Google users
  },
  twoFactorSecret: {
    type: String,
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
}, {
  timestamps: true, // Adds createdAt and updatedAt fields
});

// Mongoose pre-save middleware for hashing password
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Mongoose method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

// Mongoose virtual or method to check if locked
UserSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

module.exports = mongoose.models.User || mongoose.model('User', UserSchema); // ✅ Safe