// server.js - GenReal.ai Video, Audio & Image Detection API Backend with Auth Integration
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
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);
app.use(compression());

// Logging setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'genreal-detection-api' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// Auth service configuration
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please log in.',
        code: 'NO_TOKEN'
      });
    }

    // Validate token with auth service
    const response = await axios.get(`${AUTH_SERVICE_URL}/api/auth/validate`, {
      headers: {
        'Authorization': authHeader
      },
      timeout: 5000
    });

    if (response.data.success) {
      req.user = response.data.user;
      next();
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication token',
        code: 'INVALID_TOKEN'
      });
    }
  } catch (error) {
    logger.error('Authentication error:', error.response?.data || error.message);
    
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service unavailable',
        code: 'AUTH_SERVICE_UNAVAILABLE'
      });
    }
    
    return res.status(401).json({
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Credit deduction helper
const deductCredits = async (user, amount, analysisResult, authHeader) => {
  try {
    await axios.post(`${AUTH_SERVICE_URL}/api/auth/deduct-credits`, {
      amount,
      analysisResult: analysisResult?.result || 'analysis_completed'
    }, {
      headers: {
        'Authorization': authHeader
      },
      timeout: 5000
    });
    
    logger.info('Credits deducted successfully', {
      userId: user.id,
      amount,
      result: analysisResult?.result
    });
  } catch (error) {
    logger.error('Credit deduction failed:', {
      userId: user.id,
      amount,
      error: error.response?.data || error.message
    });
    // Don't fail the request if credit deduction fails
  }
};

// Rate limiting - more lenient for authenticated users
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests for unauthenticated
  message: { 
    success: false, 
    error: 'Too many requests from this IP, please try again later or log in for higher limits.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const authenticatedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes  
  max: 50, // 50 requests for authenticated users
  message: { 
    success: false, 
    error: 'Rate limit exceeded. Please try again later.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// File upload config
const MAX_FILE_SIZE = (process.env.MAX_FILE_SIZE_MB || 500) * 1024 * 1024;
const upload = multer({
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowedVideoTypes = [
      'video/mp4',
      'video/avi',
      'video/mov',
      'video/mkv',
      'video/webm',
      'video/quicktime',
    ];
    const allowedAudioTypes = [
      'audio/mpeg',
      'audio/wav',
      'audio/ogg',
      'audio/mp3',
      'audio/m4a',
      'audio/aac',
      'audio/webm',
    ];
    const allowedImageTypes = [
      'image/jpeg',
      'image/png',
      'image/jpg',
      'image/webp',
    ];

    const allAllowedTypes = [
      ...allowedVideoTypes,
      ...allowedAudioTypes,
      ...allowedImageTypes,
    ];

    if (allAllowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          `Unsupported file type: ${file.mimetype}. Only video, audio, and image files are allowed.`
        ),
        false
      );
    }
  },
});

// CORS configuration
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);
app.use(express.json({ limit: '10mb' }));

// Health check (public endpoint)
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'genreal-detection-api',
    authService: AUTH_SERVICE_URL 
  });
});

// Public status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    message: 'Detection service is running',
    timestamp: new Date().toISOString(),
    services: {
      deepfake: 'active',
      plagiarism: 'active',
      auth: 'connected'
    }
  });
});

// Detect file type (video, audio, image only)
const detectFileType = (file) => {
  if (file.mimetype) {
    if (file.mimetype.startsWith('video/')) return 'video';
    if (file.mimetype.startsWith('audio/')) return 'audio';
    if (file.mimetype.startsWith('image/')) return 'image';
  }
  const ext = file.originalname.toLowerCase().split('.').pop();
  const videoExt = ['mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm', 'm4v'];
  const audioExt = ['mp3', 'wav', 'ogg', 'm4a', 'aac'];
  const imageExt = ['jpg', 'jpeg', 'png', 'webp'];
  if (videoExt.includes(ext)) return 'video';
  if (audioExt.includes(ext)) return 'audio';
  if (imageExt.includes(ext)) return 'image';
  return 'unknown';
};

// Get API credentials based on type
const getApiCredentials = (fileType) => {
  switch (fileType) {
    case 'video':
      return {
        apiUrl: process.env.VIDEO_API_URL,
        tokenId: process.env.VIDEO_TOKEN_ID,
        tokenSecret: process.env.VIDEO_TOKEN_SECRET,
      };
    case 'audio':
      return {
        apiUrl: process.env.AUDIO_API_URL,
        tokenId: process.env.AUDIO_TOKEN_ID,
        tokenSecret: process.env.AUDIO_TOKEN_SECRET,
      };
    case 'image':
      return {
        apiUrl: process.env.IMAGE_API_URL,
        tokenId: process.env.IMAGE_TOKEN_ID,
        tokenSecret: process.env.IMAGE_TOKEN_SECRET,
      };
    default:
      return { apiUrl: null, tokenId: null, tokenSecret: null };
  }
};

// Get credit cost based on file type
const getCreditCost = (fileType) => {
  switch (fileType) {
    case 'video': return 3; // Video analysis costs 3 credits
    case 'audio': return 2; // Audio analysis costs 2 credits  
    case 'image': return 1; // Image analysis costs 1 credit
    default: return 1;
  }
};

// PROTECTED Analysis endpoint - requires authentication
app.post('/api/analyze', 
  authenticateUser, // Require authentication
  authenticatedLimiter, // Apply authenticated user rate limit
  upload.single('file'), 
  async (req, res) => {
    const startTime = Date.now();
    const requestId = Math.random().toString(36).substring(7);

    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No file uploaded',
          code: 'NO_FILE',
          requestId,
        });
      }

      const fileType = detectFileType(req.file);
      if (fileType === 'unknown') {
        return res.status(400).json({
          success: false,
          error: 'Invalid file type. Only video, audio and image files are supported.',
          code: 'INVALID_FILE_TYPE',
          requestId,
        });
      }

      // Check if user has enough credits
      const creditCost = getCreditCost(fileType);
      if (req.user.credits < creditCost) {
        return res.status(402).json({
          success: false,
          error: `Insufficient credits. Required: ${creditCost}, Available: ${req.user.credits}`,
          code: 'INSUFFICIENT_CREDITS',
          requiredCredits: creditCost,
          availableCredits: req.user.credits,
          requestId
        });
      }

      const { apiUrl, tokenId, tokenSecret } = getApiCredentials(fileType);
      if (!apiUrl || !tokenId || !tokenSecret) {
        return res.status(500).json({
          success: false,
          error: `${fileType.toUpperCase()} API credentials not configured`,
          requestId,
        });
      }

      logger.info('Analysis started', {
        userId: req.user.id,
        fileType,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        creditCost,
        requestId
      });

      const formData = new FormData();
      formData.append('file', req.file.buffer, {
        filename: req.file.originalname,
        contentType: req.file.mimetype,
      });

      const response = await axios.post(apiUrl, formData, {
        headers: {
          'Modal-Key': tokenId,
          'Modal-Secret': tokenSecret,
          ...formData.getHeaders(),
          'User-Agent': 'GenReal.ai/1.0',
          'X-Request-ID': requestId,
        },
        timeout:
          parseInt(process.env.REQUEST_TIMEOUT_MS, 10) ||
          (fileType === 'video' ? 300000 : 120000),
        maxContentLength: MAX_FILE_SIZE,
        maxBodyLength: MAX_FILE_SIZE,
      });

      const processingTime = Date.now() - startTime;

      const unifiedResponse = {
        success: true,
        analysisType: fileType,
        requestId,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        processingTime,
        timestamp: new Date().toISOString(),
        status: response.status,
        service: 'genreal-detection-api',
        user: {
          id: req.user.id,
          email: req.user.email,
          creditsUsed: creditCost
        },
        ...response.data,
      };

      // Deduct credits after successful analysis
      await deductCredits(
        req.user, 
        creditCost, 
        { result: response.data.result || 'analysis_completed' }, 
        req.headers.authorization
      );

      logger.info('Analysis completed successfully', {
        userId: req.user.id,
        fileType,
        processingTime,
        creditsUsed: creditCost,
        requestId
      });

      res.json(unifiedResponse);
    } catch (error) {
      handleApiError(error, res, 'universal', requestId, req.user);
    }
  }
);

// Legacy public endpoint (for backwards compatibility) - with stricter rate limiting
app.post('/api/analyze-public', 
  publicLimiter,
  upload.single('file'), 
  async (req, res) => {
    const startTime = Date.now();
    const requestId = Math.random().toString(36).substring(7);

    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No file uploaded',
          code: 'NO_FILE',
          requestId,
        });
      }

      // For public access, only allow images and limit file size
      const fileType = detectFileType(req.file);
      if (fileType !== 'image') {
        return res.status(403).json({
          success: false,
          error: 'Public access is limited to image analysis only. Please sign up for video and audio analysis.',
          code: 'PUBLIC_LIMIT_EXCEEDED',
          requestId,
        });
      }

      const { apiUrl, tokenId, tokenSecret } = getApiCredentials(fileType);
      if (!apiUrl || !tokenId || !tokenSecret) {
        return res.status(500).json({
          success: false,
          error: `${fileType.toUpperCase()} API credentials not configured`,
          requestId,
        });
      }

      const formData = new FormData();
      formData.append('file', req.file.buffer, {
        filename: req.file.originalname,
        contentType: req.file.mimetype,
      });

      const response = await axios.post(apiUrl, formData, {
        headers: {
          'Modal-Key': tokenId,
          'Modal-Secret': tokenSecret,
          ...formData.getHeaders(),
          'User-Agent': 'GenReal.ai/1.0',
          'X-Request-ID': requestId,
        },
        timeout: 60000, // 1 minute timeout for public requests
        maxContentLength: 10 * 1024 * 1024, // 10MB limit for public
        maxBodyLength: 10 * 1024 * 1024,
      });

      const processingTime = Date.now() - startTime;

      const unifiedResponse = {
        success: true,
        analysisType: fileType,
        requestId,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        processingTime,
        timestamp: new Date().toISOString(),
        status: response.status,
        service: 'genreal-detection-api',
        accessType: 'public',
        message: 'For unlimited access to video and audio analysis, please create an account.',
        ...response.data,
      };

      logger.info('Public analysis completed', {
        fileType,
        processingTime,
        requestId
      });

      res.json(unifiedResponse);
    } catch (error) {
      handleApiError(error, res, 'public', requestId);
    }
  }
);

// Error handler
const handleApiError = (error, res, analysisType, requestId, user = null) => {
  logger.error('API Error:', {
    message: error.message,
    stack: error.stack,
    analysisType,
    requestId,
    userId: user?.id
  });

  if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
    return res.status(408).json({
      success: false,
      error: 'Analysis timeout - the file is taking too long to process',
      code: 'TIMEOUT',
      requestId,
    });
  }
  if (error.response) {
    return res.status(error.response.status).json({
      success: false,
      error: 'External API error',
      code: 'EXTERNAL_API_ERROR',
      details: error.response.data,
      requestId,
    });
  }
  if (error.request) {
    return res.status(503).json({
      success: false,
      error: 'Service unavailable - unable to connect to analysis service',
      code: 'SERVICE_UNAVAILABLE',
      requestId,
    });
  }
  if (error instanceof multer.MulterError) {
    return res.status(413).json({
      success: false,
      error: 'File upload error',
      code:
        error.code === 'LIMIT_FILE_SIZE' ? 'FILE_TOO_LARGE' : 'UPLOAD_ERROR',
      details: error.message,
      maxSize: `${process.env.MAX_FILE_SIZE_MB || 500}MB`,
      requestId,
    });
  }
  return res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    requestId,
  });
};

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
  });
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', {
    message: error.message,
    stack: error.stack,
  });
  handleApiError(error, res, 'unknown', 'unknown');
});

const PORT = process.env.PORT || 3002;
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`, {
    nodeEnv: process.env.NODE_ENV,
    authServiceUrl: AUTH_SERVICE_URL
  });
  console.log(`🚀 Detection Service listening on port ${PORT}`);
  console.log(`🔐 Auth Service URL: ${AUTH_SERVICE_URL}`);
});

server.timeout = parseInt(process.env.SERVER_TIMEOUT_MS, 10) || 600000;

module.exports = app;