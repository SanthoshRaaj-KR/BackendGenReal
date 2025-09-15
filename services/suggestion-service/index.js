const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const connectDB = require('./config/db');
const Contact = require('./models/contact');
const Feedback = require('./models/feedback');

const app = express();
const PORT = process.env.PORT || 3003;

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || ['http://localhost:3000', 'http://localhost:5173'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each IP to 50 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  }
});

app.use('/api/', limiter);

// Validation middleware for Contact
const contactValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number'),
  body('subject')
    .trim()
    .isLength({ min: 5, max: 100 })
    .withMessage('Subject must be between 5 and 100 characters'),
  body('message')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Message must be between 10 and 1000 characters')
];

// Validation middleware for Feedback
const feedbackValidation = [
  body('email')
    .optional() // <-- THIS IS THE REQUIRED CHANGE
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('model')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Please select a model'),
  body('feedback')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Feedback must be between 10 and 1000 characters'),
  body('rating')
    .optional({ nullable: true, checkFalsy: false })
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  body('category')
    .optional()
    .isIn(['bug', 'feature_request', 'improvement', 'compliment', 'complaint', 'other'])
    .withMessage('Invalid category')
];

// Error handling middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'Contact & Feedback Service API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      contact: '/api/contact',
      feedback: '/api/feedback',
      admin: {
        contacts: '/api/admin/contacts',
        feedback: '/api/admin/feedback'
      }
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'contact-feedback-service',
    port: PORT
  });
});

// Contact form submission
app.post('/api/contact', contactValidation, handleValidationErrors, async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;

    const contactData = {
      name: name.trim(),
      email: email.toLowerCase().trim(),
      phone: phone ? phone.trim() : null,
      subject: subject.trim(),
      message: message.trim(),
      submittedAt: new Date(),
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    };

    const contact = new Contact(contactData);
    await contact.save();

    console.log(`📧 New contact submission: ${email} - ${subject}`);

    res.status(201).json({
      success: true,
      message: 'Contact form submitted successfully',
      data: {
        id: contact._id,
        submittedAt: contact.submittedAt
      }
    });

  } catch (error) {
    console.error('❌ Contact form submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit contact form',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Feedback form submission
app.post('/api/feedback', feedbackValidation, handleValidationErrors, async (req, res) => {
  try {
    console.log('💭 Raw feedback request body:', JSON.stringify(req.body, null, 2));
    console.log('💭 Request headers:', req.headers);
    
    const { email, model, feedback, rating, category } = req.body;

    const feedbackData = {
      email: email ? email.toLowerCase().trim() : null,
      model: model.trim(),
      feedback: feedback.trim(),
      submittedAt: new Date(),
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    };

    // Only add rating if provided and not empty
    if (rating !== undefined && rating !== null && rating !== '') {
      feedbackData.rating = parseInt(rating);
    }

    // Only add category if provided and not empty, otherwise let default handle it
    if (category && category.trim() !== '') {
      feedbackData.category = category.trim();
    }

    console.log('💭 Processed feedback data:', JSON.stringify(feedbackData, null, 2));

    const feedbackEntry = new Feedback(feedbackData);
    console.log('💭 Feedback entry before save:', JSON.stringify(feedbackEntry.toObject(), null, 2));
    
    const savedFeedback = await feedbackEntry.save();
    console.log('💭 Feedback saved successfully with ID:', savedFeedback._id);

    res.status(201).json({
      success: true,
      message: 'Feedback submitted successfully',
      data: {
        id: savedFeedback._id,
        submittedAt: savedFeedback.submittedAt,
        category: savedFeedback.category,
        priority: savedFeedback.priority
      }
    });

  } catch (error) {
    console.error('❌ Feedback submission error:', error);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error message:', error.message);
    if (error.name === 'ValidationError') {
      console.error('❌ Validation errors:', error.errors);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: Object.keys(error.errors).map(key => ({
          field: key,
          message: error.errors[key].message
        }))
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to submit feedback',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Admin routes - Get all contacts
app.get('/api/admin/contacts', async (req, res) => {
  try {
    const { status, priority, page = 1, limit = 20 } = req.query;
    
    let query = {};
    if (status) query.status = status;
    if (priority) query.priority = priority;

    const contacts = await Contact.find(query)
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Contact.countDocuments(query);

    res.json({
      success: true,
      data: contacts,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        limit
      }
    });

  } catch (error) {
    console.error('❌ Error fetching contacts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch contacts'
    });
  }
});

// Admin routes - Get all feedback
app.get('/api/admin/feedback', async (req, res) => {
  try {
    const { model, category, status, priority, page = 1, limit = 20 } = req.query;
    
    let query = {};
    if (model) query.model = model;
    if (category) query.category = category;
    if (status) query.status = status;
    if (priority) query.priority = priority;

    const feedback = await Feedback.find(query)
      .sort({ submittedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Feedback.countDocuments(query);

    res.json({
      success: true,
      data: feedback,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        limit
      }
    });

  } catch (error) {
    console.error('❌ Error fetching feedback:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch feedback'
    });
  }
});

// Admin routes - Get feedback statistics
app.get('/api/admin/feedback/stats', async (req, res) => {
  try {
    const { model } = req.query;
    let matchQuery = {};
    if (model) matchQuery.model = model;

    const stats = await Feedback.aggregate([
      { $match: matchQuery },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          avgRating: { $avg: '$rating' },
          categories: {
            $push: '$category'
          },
          priorities: {
            $push: '$priority'
          }
        }
      }
    ]);

    const categoryStats = await Feedback.aggregate([
      { $match: matchQuery },
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);

    const modelStats = await Feedback.aggregate([
      { $group: { _id: '$model', count: { $sum: 1 }, avgRating: { $avg: '$rating' } } },
      { $sort: { count: -1 } }
    ]);

    res.json({
      success: true,
      data: {
        overview: stats[0] || { total: 0, avgRating: 0 },
        byCategory: categoryStats,
        byModel: modelStats
      }
    });

  } catch (error) {
    console.error('❌ Error fetching feedback stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch feedback statistics'
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Contact & Feedback service running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: MongoDB`);
  console.log(`🔗 Available endpoints:`);
  console.log(`   - POST /api/contact (Contact submissions)`);
  console.log(`   - POST /api/feedback (Feedback submissions)`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});