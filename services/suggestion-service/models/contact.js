const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },
  phone: {
    type: String,
    trim: true,
    default: null
  },
  subject: {
    type: String,
    required: true,
    trim: true,
    maxlength: [100, 'Subject cannot exceed 100 characters']
  },
  message: {
    type: String,
    required: true,
    trim: true,
    maxlength: [1000, 'Message cannot exceed 1000 characters']
  },
  submittedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  // Metadata
  status: {
    type: String,
    enum: ['pending', 'reviewed', 'responded', 'closed'],
    default: 'pending',
    index: true
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  
  // Admin fields
  assignedTo: {
    type: String,
    default: null
  },
  adminNotes: {
    type: String,
    default: null
  },
  respondedAt: {
    type: Date,
    default: null
  },
  
  // Tags for categorization
  tags: [{
    type: String,
    trim: true
  }]
}, {
  timestamps: true,
  versionKey: false
});

// Indexes for better query performance
contactSchema.index({ email: 1 });
contactSchema.index({ status: 1, priority: 1 });
contactSchema.index({ submittedAt: -1 });

// Virtual for formatted submission date
contactSchema.virtual('formattedDate').get(function() {
  return this.submittedAt.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
});

// Virtual for response time (if responded)
contactSchema.virtual('responseTime').get(function() {
  if (this.respondedAt && this.submittedAt) {
    const timeDiff = this.respondedAt - this.submittedAt;
    const hours = Math.floor(timeDiff / (1000 * 60 * 60));
    return hours;
  }
  return null;
});

// Pre-save middleware to set priority based on content
contactSchema.pre('save', function(next) {
  if (this.isNew) {
    // Set priority based on keywords in subject/message
    const urgentKeywords = ['urgent', 'emergency', 'critical', 'asap', 'immediately'];
    const highKeywords = ['important', 'priority', 'escalate', 'manager'];
    
    const content = `${this.subject} ${this.message}`.toLowerCase();
    
    if (urgentKeywords.some(keyword => content.includes(keyword))) {
      this.priority = 'urgent';
    } else if (highKeywords.some(keyword => content.includes(keyword))) {
      this.priority = 'high';
    }
  }
  next();
});

// Static method to get pending submissions
contactSchema.statics.getPending = function() {
  return this.find({ status: 'pending' }).sort({ priority: 1, submittedAt: -1 });
};

// Instance method to mark as reviewed
contactSchema.methods.markAsReviewed = function(adminId) {
  this.status = 'reviewed';
  this.assignedTo = adminId;
  return this.save();
};

// Instance method to mark as responded
contactSchema.methods.markAsResponded = function(adminNotes) {
  this.status = 'responded';
  this.respondedAt = new Date();
  if (adminNotes) {
    this.adminNotes = adminNotes;
  }
  return this.save();
};

const Contact = mongoose.model('Contact', contactSchema);

module.exports = Contact;