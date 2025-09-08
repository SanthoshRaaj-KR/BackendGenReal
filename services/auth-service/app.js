const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const session = require('express-session');
require('dotenv').config();

// Import Passport configuration
const passport = require('./src/config/passport');

const securityMiddleware = require('./src/middleware/security');
const authRoutes = require('./src/routes/authRoutes');
const connectDB = require('./src/config/database');

const app = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', 1);

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==============================================================
//  2. ADD AND CONFIGURE SESSION MIDDLEWARE (THE FIX)
// ==============================================================
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false, // Set to false, good practice
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax', // VERY IMPORTANT for OAuth redirects
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Initialize Passport middleware (MUST be after session)
app.use(passport.initialize());
app.use(passport.session()); // <-- 3. ENABLE PASSPORT SESSIONS

app.use(securityMiddleware);

app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is running',
    timestamp: new Date().toISOString(),
    service: 'auth-service',
    version: process.env.npm_package_version || '1.0.0',
  });
});

app.use('/api/auth', authRoutes);

// ... (The rest of your file is perfect, no more changes needed) ...

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  let error = { ...err };
  error.message = err.message;
  
  if (err.code === 11000) {
    const message = 'Resource already exists';
    return res.status(409).json({ success: false, message });
  }
  
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => ({
      field: val.path,
      message: val.message,
    }));
    return res.status(400).json({ success: false, message: 'Validation failed', errors });
  }
  
  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

const startServer = async () => {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(`Auth service running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`Google OAuth configured: ${process.env.GOOGLE_CLIENT_ID ? 'Yes' : 'No'}`);
      console.log('Using MongoDB for OTP storage (Redis removed)');
    });
  } catch (error) {
    console.error('Unable to start server:', error);
    process.exit(1);
  }
};

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});
process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});

startServer();
module.exports = app;
