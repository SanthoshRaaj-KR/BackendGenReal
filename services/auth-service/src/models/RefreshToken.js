
const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User', // Creates a reference to the User model
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  isRevoked: {
    type: Boolean,
    default: false,
  },
  deviceInfo: {
    type: Object, // Mongoose can store nested JSON objects
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);