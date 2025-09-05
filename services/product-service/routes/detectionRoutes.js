// Create this file: services/detection-service/routes/detectionRoutes.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

// Auth service URL
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';

// Middleware to verify authentication with auth service
const authenticateWithAuthService = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'NO_TOKEN'
      });
    }

    // Forward the request to auth service for validation
    const response = await axios.get(`${AUTH_SERVICE_URL}/api/auth/validate`, {
      headers: {
        'Authorization': authHeader
      }
    });

    if (response.data.success) {
      req.user = response.data.user;
      next();
    } else {
      return res.status(401).json({
        success: false,
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
  } catch (error) {
    console.error('Auth verification error:', error.response?.data || error.message);
    return res.status(401).json({
      success: false,
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Credit deduction helper
const deductCredits = async (userId, amount, analysisResult) => {
  try {
    const authHeader = req.headers.authorization;
    await axios.post(`${AUTH_SERVICE_URL}/api/auth/deduct-credits`, {
      amount,
      analysisResult
    }, {
      headers: {
        'Authorization': authHeader
      }
    });
  } catch (error) {
    console.error('Credit deduction error:', error.response?.data || error.message);
  }
};

/**
 * @desc    Upload and analyze deepfake content
 * @route   POST /api/detection/deepfake
 * @access  Private
 */
router.post('/deepfake', authenticateWithAuthService, async (req, res) => {
  try {
    console.log('Deepfake detection request from user:', req.user.email);
    
    // Check if user has enough credits (minimum 1)
    if (req.user.credits < 1) {
      return res.status(402).json({
        success: false,
        message: 'Insufficient credits for deepfake analysis',
        code: 'INSUFFICIENT_CREDITS'
      });
    }

    // Your deepfake detection logic here
    // This is a mock implementation
    const analysisResult = {
      confidence: Math.floor(Math.random() * 40) + 60, // 60-100%
      result: Math.random() > 0.3 ? 'authentic' : 'suspicious',
      details: 'Analysis completed successfully',
      timestamp: new Date().toISOString()
    };

    // Deduct credits
    try {
      await axios.post(`${AUTH_SERVICE_URL}/api/auth/deduct-credits`, {
        amount: 1,
        analysisResult: analysisResult.result
      }, {
        headers: {
          'Authorization': req.headers.authorization
        }
      });
    } catch (creditError) {
      console.error('Failed to deduct credits:', creditError.response?.data);
    }

    res.json({
      success: true,
      message: 'Deepfake analysis completed successfully',
      data: analysisResult
    });
  } catch (error) {
    console.error('Deepfake detection error:', error);
    res.status(500).json({
      success: false,
      message: 'Deepfake analysis failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * @desc    Upload and analyze plagiarism content
 * @route   POST /api/detection/plagiarism
 * @access  Private
 */
router.post('/plagiarism', authenticateWithAuthService, async (req, res) => {
  try {
    console.log('Plagiarism detection request from user:', req.user.email);
    
    // Check if user has enough credits (minimum 2 for plagiarism)
    if (req.user.credits < 2) {
      return res.status(402).json({
        success: false,
        message: 'Insufficient credits for plagiarism analysis (requires 2 credits)',
        code: 'INSUFFICIENT_CREDITS'
      });
    }

    // Your plagiarism detection logic here
    // This is a mock implementation
    const analysisResult = {
      confidence: Math.floor(Math.random() * 30) + 70, // 70-100%
      result: Math.random() > 0.4 ? 'authentic' : 'suspicious',
      plagiarismPercentage: Math.floor(Math.random() * 15), // 0-15%
      sources: [],
      details: 'Plagiarism analysis completed',
      timestamp: new Date().toISOString()
    };

    // Deduct credits
    try {
      await axios.post(`${AUTH_SERVICE_URL}/api/auth/deduct-credits`, {
        amount: 2,
        analysisResult: analysisResult.result
      }, {
        headers: {
          'Authorization': req.headers.authorization
        }
      });
    } catch (creditError) {
      console.error('Failed to deduct credits:', creditError.response?.data);
    }

    res.json({
      success: true,
      message: 'Plagiarism analysis completed successfully',
      data: analysisResult
    });
  } catch (error) {
    console.error('Plagiarism detection error:', error);
    res.status(500).json({
      success: false,
      message: 'Plagiarism analysis failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * @desc    Get user's analysis history
 * @route   GET /api/detection/history
 * @access  Private
 */
router.get('/history', authenticateWithAuthService, async (req, res) => {
  try {
    // This is a mock implementation
    // In a real app, you'd fetch this from a database
    const mockHistory = [
      {
        id: 1,
        type: 'deepfake',
        result: 'authentic',
        confidence: 87.5,
        timestamp: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
        creditsUsed: 1
      },
      {
        id: 2,
        type: 'plagiarism',
        result: 'suspicious',
        confidence: 92.3,
        plagiarismPercentage: 12,
        timestamp: new Date(Date.now() - 172800000).toISOString(), // 2 days ago
        creditsUsed: 2
      }
    ];

    res.json({
      success: true,
      data: {
        history: mockHistory,
        totalAnalyses: mockHistory.length,
        user: {
          email: req.user.email,
          credits: req.user.credits
        }
      }
    });
  } catch (error) {
    console.error('History fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch analysis history'
    });
  }
});

/**
 * @desc    Get service status
 * @route   GET /api/detection/status
 * @access  Public
 */
router.get('/status', (req, res) => {
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

module.exports = router;