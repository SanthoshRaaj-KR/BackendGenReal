const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true, // Automatically convert to lowercase
    trim: true, // Remove whitespace
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email',
    ],
  },
  password: {
    type: String,
    // Required is a function to allow null for OAuth users
    required: function() { return !this.googleId; },
    minlength: [6, 'Password must be at least 6 characters long'], // Changed from 8 to 6 to match frontend
    select: false, // Don't send password back in queries by default
  },
  firstName: {
    type: String,
    required: [true, 'Please provide a first name'],
    trim: true,
  },
  lastName: {
    type: String,
    required: false, // Changed to false since your frontend allows empty last names
    trim: true,
    default: '', // Default to empty string
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
  // ✅ NEW FIELDS FOR CREDITS SYSTEM
  credits: {
    type: Number,
    default: 100, // Give new users 100 free credits
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
  // ✅ ANALYTICS FIELDS FOR DASHBOARD
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
  subscription: {
    stripeCustomerId: String,
    stripeSubscriptionId: String,
    status: {
      type: String,
      enum: ['active', 'canceled', 'past_due', 'incomplete'],
    },
    currentPeriodEnd: Date,
  },
}, {
  timestamps: true, // Adds createdAt and updatedAt fields
});

// Index for better performance
UserSchema.index({ email: 1 });
UserSchema.index({ googleId: 1 });
UserSchema.index({ createdAt: -1 });

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

// ✅ NEW METHODS FOR CREDITS MANAGEMENT
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

// ✅ METHOD TO UPDATE ANALYSIS STATS
UserSchema.methods.recordAnalysis = function(result, creditsUsed = 0) {
  this.analysesPerformed += 1;
  this.deductCredits(creditsUsed);
  
  if (result && result.toLowerCase().includes('authentic')) {
    this.authenticResults += 1;
  } else if (result && (result.toLowerCase().includes('suspicious') || result.toLowerCase().includes('fake'))) {
    this.suspiciousResults += 1;
  }
  
  return this.save();
};

// ✅ VIRTUAL FOR FULL NAME
UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`.trim();
});

// ✅ VIRTUAL FOR REMAINING CREDITS PERCENTAGE
UserSchema.virtual('creditUsagePercentage').get(function() {
  const totalEverHad = this.credits + this.totalCreditsUsed;
  if (totalEverHad === 0) return 0;
  return Math.round((this.totalCreditsUsed / totalEverHad) * 100);
});

// ✅ VIRTUAL FOR AVERAGE CONFIDENCE (you can implement this based on your analysis storage)
UserSchema.virtual('averageConfidence').get(function() {
  // This is a placeholder - you might want to calculate this from your analysis records
  return 85.7; // Default value for now
});

// ✅ METHOD TO GET DASHBOARD STATS
UserSchema.methods.getDashboardStats = function() {
  return {
    totalAnalyses: this.analysesPerformed,
    authenticContent: this.authenticResults,
    suspiciousContent: this.suspiciousResults,
    averageConfidence: this.averageConfidence || 85.7,
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

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);