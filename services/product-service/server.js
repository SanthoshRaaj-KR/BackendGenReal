// server.js - GenReal.ai Video Detection API Backend
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const winston = require('winston');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression());

// Logging setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'genreal-video-detection-api' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// Rate limiting - now configured from .env
const apiLimiter = rateLimit({
  windowMs: (process.env.RATE_LIMIT_WINDOW_MINUTES || 15) * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 10,
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false
});

// File upload configuration - now configured from .env
const MAX_FILE_SIZE = (process.env.MAX_FILE_SIZE_MB || 500) * 1024 * 1024;
const upload = multer({
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/mkv', 'video/webm'];
    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}. Only video files are allowed.`), false);
    }
  }
});

// CORS configuration - now configured from .env
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Service status endpoint
app.get('/api/status', async (req, res) => {
  const videoApiUrl = process.env.VIDEO_API_URL;
  if (!videoApiUrl) return res.status(500).json({ error: 'VIDEO_API_URL is not configured' });
  
  try {
    const services = { videoAPI: { status: 'unknown', responseTime: null } };
    try {
      const start = Date.now();
      await axios.get(`${videoApiUrl}/health`, {
        timeout: 5000,
        headers: {
          'Modal-Key': process.env.TOKEN_ID,
          'Modal-Secret': process.env.TOKEN_SECRET
        }
      });
      services.videoAPI = { status: 'healthy', responseTime: Date.now() - start };
    } catch (error) {
      services.videoAPI.status = 'unhealthy';
      services.videoAPI.error = error.message;
    }
    res.json({
      overall: services.videoAPI.status === 'healthy' ? 'healthy' : 'degraded',
      services,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Status check failed:', error);
    res.status(500).json({ error: 'Status check failed' });
  }
});

// File type detection utility
const detectFileType = (file) => {
    if (file.mimetype && file.mimetype.startsWith('video/')) return 'video';
    const ext = file.originalname.toLowerCase().split('.').pop();
    const videoExtensions = ['mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm', 'm4v'];
    if (videoExtensions.includes(ext)) return 'video';
    return 'unknown';
};

// Video analysis endpoint
app.post('/api/analyze/video', apiLimiter, upload.single('file'), async (req, res) => {
    const videoApiUrl = process.env.VIDEO_API_URL;
    if (!videoApiUrl) return res.status(500).json({ error: 'VIDEO_API_URL is not configured' });
    
    const startTime = Date.now();
    const requestId = Math.random().toString(36).substring(7);
  
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded', code: 'NO_FILE', requestId });
    }
    if (detectFileType(req.file) !== 'video') {
      return res.status(400).json({ error: 'Invalid file type. Only video is allowed.', code: 'INVALID_FILE_TYPE', requestId });
    }
    
    const formData = new FormData();
    formData.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    const response = await axios.post(videoApiUrl, formData, {
      headers: {
        'Modal-Key': process.env.TOKEN_ID,
        'Modal-Secret': process.env.TOKEN_SECRET,
        ...formData.getHeaders(),
        'User-Agent': 'GenReal.ai/1.0',
        'X-Request-ID': requestId
      },
      timeout: parseInt(process.env.REQUEST_TIMEOUT_MS, 10) || 300000,
      maxContentLength: MAX_FILE_SIZE,
      maxBodyLength: MAX_FILE_SIZE
    });

    res.json({
      ...response.data,
      metadata: {
        requestId,
        analysisType: 'video',
        fileName: req.file.originalname,
        fileSize: req.file.size,
        processingTime: Date.now() - startTime,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    handleApiError(error, res, 'video', requestId);
  }
});

// Global error handler
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', { message: error.message, stack: error.stack });
    handleApiError(error, res, 'unknown', 'unknown');
});

// All other functions (handleApiError, 404 handler, graceful shutdown, server start) remain largely the same...

// Enhanced error handling
const handleApiError = (error, res, analysisType, requestId) => {
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
        return res.status(408).json({ error: `Analysis timeout`, code: 'TIMEOUT', requestId });
    }
    if (error.response) {
        return res.status(error.response.status).json({ error: `External API error`, code: 'EXTERNAL_API_ERROR', details: error.response.data, requestId });
    }
    if (error.request) {
        return res.status(503).json({ error: `Service unavailable`, code: 'SERVICE_UNAVAILABLE', requestId });
    }
    if (error instanceof multer.MulterError) {
        return res.status(413).json({ error: 'File upload error', code: error.code === 'LIMIT_FILE_SIZE' ? 'FILE_TOO_LARGE' : 'UPLOAD_ERROR', details: error.message, maxSize: `${process.env.MAX_FILE_SIZE_MB || 500}MB`, requestId });
    }
    if (error.message.includes('Unsupported file type') || error.message.includes('CORS')) {
        return res.status(400).json({ error: 'Bad Request', code: 'BAD_REQUEST', details: error.message, requestId });
    }
    return res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR', requestId });
};

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found', code: 'NOT_FOUND' });
});

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`, { nodeEnv: process.env.NODE_ENV });
  console.log(`🚀 Server listening on port ${PORT}`);
});

server.timeout = parseInt(process.env.SERVER_TIMEOUT_MS, 10) || 600000;

module.exports = app;