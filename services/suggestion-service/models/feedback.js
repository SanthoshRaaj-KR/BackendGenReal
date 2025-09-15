const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  model: {
    type: String,
    required: true,
    trim: true
  },
  feedback: {
    type: String,
    required: true,
    trim: true
  },
  rating: {
    type: Number,
    min: 1,
    max: 5,
    default: null
  },
  category: {
    type: String,
    enum: ['bug', 'feature_request', 'improvement', 'compliment', 'complaint', 'other'],
    default: 'other'
  },
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'resolved'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  submittedAt: {
    type: Date,
    default: Date.now
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  }
}, {
  timestamps: true,
  versionKey: false
});

// Add indexes for better performance
feedbackSchema.index({ email: 1 });
feedbackSchema.index({ model: 1 });
feedbackSchema.index({ category: 1 });
feedbackSchema.index({ status: 1 });
feedbackSchema.index({ priority: 1 });
feedbackSchema.index({ submittedAt: -1 });

module.exports = mongoose.model('Feedback', feedbackSchema);