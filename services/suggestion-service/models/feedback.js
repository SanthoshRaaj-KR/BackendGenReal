// models/Feedback.js
const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
  type: { type: String, default: 'feedback' },
  email: { type: String, required: true },
  model: { type: String, required: true },
  feedback: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
  ipAddress: String,
  userAgent: String
});

module.exports = mongoose.model('Feedback', feedbackSchema);
