const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// =====================================
// CONFIGURATION & VALIDATION
// =====================================

// Validate environment variables
const requiredEnvVars = [
  'VIDEO_API_URL', 'VIDEO_TOKEN_ID', 'VIDEO_TOKEN_SECRET',
  'IMAGE_API_URL', 'IMAGE_TOKEN_ID', 'IMAGE_TOKEN_SECRET', 
  'AUDIO_API_URL', 'AUDIO_TOKEN_ID', 'AUDIO_TOKEN_SECRET',
  'CODE_API_URL', 'CODE_TOKEN_ID', 'CODE_TOKEN_SECRET'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const config = {
  port: process.env.PORT || 3002,
  nodeEnv: process.env.NODE_ENV || 'development',
  allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  rateLimit: {
    windowMinutes: parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 10
  },
  maxFileSize: (parseInt(process.env.MAX_FILE_SIZE_MB) || 500) * 1024 * 1024,
  requestTimeout: parseInt(process.env.REQUEST_TIMEOUT_MS) || 360000,
  serverTimeout: parseInt(process.env.SERVER_TIMEOUT_MS) || 600000
};

console.log('🔧 Server configuration:', {
  port: config.port,
  nodeEnv: config.nodeEnv,
  allowedOrigins: config.allowedOrigins,
  maxFileSize: `${config.maxFileSize / (1024 * 1024)}MB`,
  requestTimeout: `${config.requestTimeout / 1000}s`
});

// =====================================
// MIDDLEWARE SETUP
// =====================================

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow for API usage
}));

// Compression middleware
app.use(compression());

// Logging middleware
if (config.nodeEnv === 'production') {
  app.use(morgan('combined'));
} else {
  app.use(morgan('dev'));
}

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (config.allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn(`🚫 Blocked CORS request from: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const rateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMinutes * 60 * 1000,
  max: config.rateLimit.maxRequests,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: `${config.rateLimit.windowMinutes} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`🚫 Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: `${config.rateLimit.windowMinutes} minutes`
    });
  }
});

app.use('/api/', rateLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configure multer for file uploads
const upload = multer({
  limits: {
    fileSize: config.maxFileSize,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Allow specific file types
    const allowedTypes = [
      // Video
      'video/mp4', 'video/avi', 'video/mov', 'video/mkv', 'video/wmv', 
      'video/flv', 'video/webm', 'video/quicktime',
      // Audio  
      'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/m4a', 'audio/aac', 
      'audio/flac', 'audio/opus', 'audio/mp3',
      // Image
      'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 
      'image/bmp', 'image/tiff',
      // Code files
      'text/plain', 'text/x-python', 'application/javascript', 'text/x-java-source',
      'text/x-c++src', 'text/x-csrc', 'application/json'
    ];

    const fileExtension = file.originalname.toLowerCase().split('.').pop();
    const codeExtensions = [
      'py', 'js', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb', 'go', 
      'rs', 'swift', 'kt', 'ts', 'jsx', 'vue', 'html', 'css', 'scss', 
      'sql', 'r', 'scala', 'sh', 'bat', 'ps1', 'json', 'xml', 'yaml', 'yml'
    ];

    if (allowedTypes.includes(file.mimetype) || codeExtensions.includes(fileExtension)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype || 'unknown'}`), false);
    }
  }
});

// =====================================
// UTILITY FUNCTIONS
// =====================================

const getFileType = (file) => {
  if (!file) return 'unknown';
  
  // Check MIME type first
  if (file.mimetype) {
    if (file.mimetype.startsWith('video/')) return 'video';
    if (file.mimetype.startsWith('image/')) return 'image';
    if (file.mimetype.startsWith('audio/')) return 'audio';
  }

  // Fallback to file extension
  const ext = file.originalname.toLowerCase().split('.').pop();
  const videoExt = ['mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm', 'm4v', 'quicktime'];
  const imageExt = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff'];
  const audioExt = ['mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac', 'opus'];
  const codeExt = ['py', 'js', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb', 'go', 'rs', 'swift', 'kt', 'ts', 'jsx', 'vue', 'html', 'css', 'scss', 'sql', 'r', 'scala', 'sh', 'bat', 'ps1', 'json', 'xml', 'yaml', 'yml'];

  if (videoExt.includes(ext)) return 'video';
  if (imageExt.includes(ext)) return 'image';
  if (audioExt.includes(ext)) return 'audio';
  if (codeExt.includes(ext)) return 'code';
  
  return 'unknown';
};

const getApiConfig = (fileType) => {
  switch (fileType) {
    case 'video':
      return {
        url: process.env.VIDEO_API_URL,
        tokenId: process.env.VIDEO_TOKEN_ID,
        tokenSecret: process.env.VIDEO_TOKEN_SECRET,
        timeout: config.requestTimeout
      };
    case 'image':
      return {
        url: process.env.IMAGE_API_URL,
        tokenId: process.env.IMAGE_TOKEN_ID,
        tokenSecret: process.env.IMAGE_TOKEN_SECRET,
        timeout: config.requestTimeout
      };
    case 'audio':
      return {
        url: process.env.AUDIO_API_URL,
        tokenId: process.env.AUDIO_TOKEN_ID,
        tokenSecret: process.env.AUDIO_TOKEN_SECRET,
        timeout: config.requestTimeout
      };
    case 'code':
      return {
        url: process.env.CODE_API_URL,
        tokenId: process.env.CODE_TOKEN_ID,
        tokenSecret: process.env.CODE_TOKEN_SECRET,
        timeout: config.requestTimeout
      };
    default:
      throw new Error(`Unsupported file type: ${fileType}`);
  }
};

const handleApiError = (error, res, type) => {
  const errorDetails = {
    message: error.message,
    status: error.response?.status,
    data: error.response?.data,
    url: error.config?.url
  };

  console.error(`❌ ${type} API error:`, errorDetails);

  if (error.code === 'ECONNABORTED') {
    return res.status(408).json({
      error: `Request timeout - ${type} analysis took too long`,
      details: 'The file may be too large or the service is experiencing high load',
      retryAfter: 300
    });
  }

  if (error.response) {
    const status = error.response.status;
    const message = error.response.data?.error || error.response.data || `${type} API Error`;
    
    return res.status(status >= 400 && status < 600 ? status : 500).json({
      error: message,
      details: error.response.statusText,
      service: type
    });
  } 
  
  if (error.request) {
    return res.status(503).json({
      error: `Unable to reach ${type} analysis service`,
      details: 'The service may be temporarily unavailable',
      retryAfter: 60
    });
  }

  return res.status(500).json({
    error: 'Internal server error',
    details: error.message,
    service: type
  });
};

// =====================================
// API ENDPOINTS
// =====================================

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: config.nodeEnv,
    uptime: process.uptime()
  });
});

// Deepfake analysis endpoint (handles video, image, audio)
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  const startTime = Date.now();
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No file uploaded',
        supportedTypes: ['video', 'image', 'audio']
      });
    }

    const fileType = getFileType(req.file);
    
    if (fileType === 'unknown' || fileType === 'code') {
      return res.status(400).json({
        error: `Unsupported file type for deepfake analysis: ${fileType}`,
        supportedTypes: ['video', 'image', 'audio'],
        receivedFile: {
          name: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size
        }
      });
    }

    console.log(`🔍 Analyzing ${fileType.toUpperCase()} file:`, {
      name: req.file.originalname,
      mimetype: req.file.mimetype,
      size: `${(req.file.size / (1024 * 1024)).toFixed(2)}MB`,
      type: fileType
    });

    const apiConfig = getApiConfig(fileType);

    // Prepare form data for API request
    const formData = new FormData();
    formData.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    console.log(`📡 Sending request to ${fileType.toUpperCase()} API: ${apiConfig.url}`);

    const response = await axios.post(apiConfig.url, formData, {
      headers: {
        'Modal-Key': apiConfig.tokenId,
        'Modal-Secret': apiConfig.tokenSecret,
        ...formData.getHeaders()
      },
      timeout: apiConfig.timeout,
      maxContentLength: config.maxFileSize,
      maxBodyLength: config.maxFileSize
    });

    const processingTime = Date.now() - startTime;

    console.log(`✅ ${fileType.toUpperCase()} API response (${processingTime}ms):`, {
      status: response.status,
      dataKeys: Object.keys(response.data || {})
    });

    // Log the full response for debugging
    console.log('🔍 Full API Response:', JSON.stringify(response.data, null, 2));

    // Return the response with additional metadata
    const result = {
      ...response.data,
      analysisType: fileType,
      processingTime,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      timestamp: new Date().toISOString()
    };

    res.json(result);

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error(`❌ Analysis failed after ${processingTime}ms:`, error.message);
    
    const fileType = req.file ? getFileType(req.file) : 'unknown';
    handleApiError(error, res, fileType);
  }
});

// Code plagiarism check endpoint
app.post('/api/plagiarism/check', upload.single('file'), async (req, res) => {
  const startTime = Date.now();
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No code file uploaded',
        supportedTypes: ['code files (.py, .js, .java, .cpp, etc.)']
      });
    }

    const fileType = getFileType(req.file);
    
    if (fileType !== 'code') {
      return res.status(400).json({
        error: 'Only code files are supported for plagiarism checking',
        receivedType: fileType,
        supportedExtensions: ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.ts']
      });
    }

    const fileContent = req.file.buffer.toString('utf8');
    const language = req.body.language || 'unknown';

    if (!fileContent.trim()) {
      return res.status(400).json({ error: 'Code file appears to be empty' });
    }

    console.log(`🔍 Checking code plagiarism:`, {
      filename: req.file.originalname,
      language: language,
      size: `${fileContent.length} characters`,
      lines: fileContent.split('\n').length
    });

    // Get code API configuration from environment variables
    const apiConfig = getApiConfig('code');

    const formData = new FormData();
    formData.append('code', fileContent);

    console.log(`📡 Sending request to Code Plagiarism API: ${apiConfig.url}`);

    const response = await axios.post(apiConfig.url, formData, {
      headers: {
        'Modal-Key': apiConfig.tokenId,
        'Modal-Secret': apiConfig.tokenSecret,
        ...formData.getHeaders()
      },
      timeout: apiConfig.timeout,
      maxContentLength: config.maxFileSize,
      maxBodyLength: config.maxFileSize
    });

    const processingTime = Date.now() - startTime;

    console.log(`✅ Code Plagiarism API response (${processingTime}ms):`, {
      status: response.status,
      dataKeys: Object.keys(response.data || {})
    });

    // Log the full response for debugging
    console.log('🔍 Full Code API Response:', JSON.stringify(response.data, null, 2));

    // Format response for consistency
    const result = {
      ...response.data,
      analysisType: 'code',
      language: language,
      processingTime,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      codeLength: fileContent.length,
      linesOfCode: fileContent.split('\n').length,
      timestamp: new Date().toISOString()
    };

    res.json(result);

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error(`❌ Code plagiarism check failed after ${processingTime}ms:`, error.message);
    
    handleApiError(error, res, 'Code');
  }
});

// =====================================
// ERROR HANDLING & SERVER SETUP
// =====================================

// Global error handler
app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'File too large',
        maxSize: `${config.maxFileSize / (1024 * 1024)}MB`,
        details: error.message
      });
    }
    return res.status(400).json({
      error: 'File upload error',
      details: error.message,
      code: error.code
    });
  }

  res.status(500).json({
    error: 'Internal server error',
    message: config.nodeEnv === 'production' ? 'Something went wrong' : error.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /health',
      'POST /api/analyze (video/image/audio deepfake detection)',
      'POST /api/plagiarism/check (code plagiarism detection)'
    ]
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// Start server
const server = app.listen(config.port, () => {
  console.log(`🚀 Production server running on port ${config.port}`);
  console.log(`🌐 Environment: ${config.nodeEnv}`);
  console.log(`📊 Health check: http://localhost:${config.port}/health`);
  console.log(`🔍 Deepfake API: http://localhost:${config.port}/api/analyze`);
  console.log(`💻 Code Plagiarism API: http://localhost:${config.port}/api/plagiarism/check`);
  console.log(`📝 Text Plagiarism API: http://localhost:${config.port}/api/plagiarism/check/text`);
  console.log(`📁 Code File Plagiarism API: http://localhost:${config.port}/api/plagiarism/check/code`);
  console.log(`⚡ Max file size: ${config.maxFileSize / (1024 * 1024)}MB`);
  console.log(`🔒 Rate limit: ${config.rateLimit.maxRequests} requests per ${config.rateLimit.windowMinutes} minutes`);
});

// Set server timeout
server.setTimeout(config.serverTimeout);

module.exports = app;