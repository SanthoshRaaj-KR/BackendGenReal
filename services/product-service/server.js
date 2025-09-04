// server.js - GenReal.ai Video, Audio & Image Detection API Backend
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

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: (process.env.RATE_LIMIT_WINDOW_MINUTES || 15) * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 10,
  message: { error: 'Too many requests from this IP, please try again later.' },
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

// CORS - Allow all origins for now (restrict in production)
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);
app.use(express.json({ limit: '10mb' }));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
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

// Analysis endpoint
app.post('/api/analyze', apiLimiter, upload.single('file'), async (req, res) => {
  const startTime = Date.now();
  const requestId = Math.random().toString(36).substring(7);

  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded',
        code: 'NO_FILE',
        requestId,
      });
    }

    const fileType = detectFileType(req.file);
    if (fileType === 'unknown') {
      return res.status(400).json({
        error: 'Invalid file type. Only video, audio and image files are supported.',
        code: 'INVALID_FILE_TYPE',
        requestId,
      });
    }

    const { apiUrl, tokenId, tokenSecret } = getApiCredentials(fileType);
    if (!apiUrl || !tokenId || !tokenSecret) {
      return res.status(500).json({
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
      timeout:
        parseInt(process.env.REQUEST_TIMEOUT_MS, 10) ||
        (fileType === 'video' ? 300000 : 120000),
      maxContentLength: MAX_FILE_SIZE,
      maxBodyLength: MAX_FILE_SIZE,
    });

    const processingTime = Date.now() - startTime;

    const unifiedResponse = {
      analysisType: fileType,
      requestId,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      processingTime,
      timestamp: new Date().toISOString(),
      status: response.status,
      service: 'genreal-detection-api',
      ...response.data,
    };

    logger.info('API Response', unifiedResponse);

    res.json(unifiedResponse);
  } catch (error) {
    handleApiError(error, res, 'universal', requestId);
  }
});

// Error handler
const handleApiError = (error, res, analysisType, requestId) => {
  logger.error('API Error:', {
    message: error.message,
    stack: error.stack,
    analysisType,
    requestId,
  });

  if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
    return res.status(408).json({
      error: 'Analysis timeout - the file is taking too long to process',
      code: 'TIMEOUT',
      requestId,
    });
  }
  if (error.response) {
    return res.status(error.response.status).json({
      error: 'External API error',
      code: 'EXTERNAL_API_ERROR',
      details: error.response.data,
      requestId,
    });
  }
  if (error.request) {
    return res.status(503).json({
      error: 'Service unavailable - unable to connect to analysis service',
      code: 'SERVICE_UNAVAILABLE',
      requestId,
    });
  }
  if (error instanceof multer.MulterError) {
    return res.status(413).json({
      error: 'File upload error',
      code:
        error.code === 'LIMIT_FILE_SIZE' ? 'FILE_TOO_LARGE' : 'UPLOAD_ERROR',
      details: error.message,
      maxSize: `${process.env.MAX_FILE_SIZE_MB || 500}MB`,
      requestId,
    });
  }
  return res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    requestId,
  });
};

// 404
app.use((req, res) => {
  res.status(404).json({
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
  });
  console.log(`🚀 Server listening on port ${PORT}`);
});

server.timeout = parseInt(process.env.SERVER_TIMEOUT_MS, 10) || 600000;

module.exports = app;
