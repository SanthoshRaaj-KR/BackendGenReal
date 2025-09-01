// Example: services/detection-service/routes/detectionRoutes.js
const express = require('express');
const { authenticate, requireCredits, adminOnly } = require('../middleware/auth'); // Import from auth service
const router = express.Router();

// ============================================
// PROTECTED ROUTES - REQUIRE AUTHENTICATION
// ============================================

/**
 * @desc    Upload and analyze deepfake content
 * @route   POST /api/detection/deepfake
 * @access  Private (requires auth + 1 credit)
 */
router.post('/deepfake', 
  authenticate,              // Must be logged in
  requireCredits(1),         // Must have at least 1 credit
  async (req, res) => {
    try {
      // Your deepfake detection logic here
      console.log('Authenticated user:', req.user.email);
      console.log('Credits available:', req.user.credits);
      
      // Simulate deepfake analysis
      const analysisResult = {
        confidence: 87.5,
        result: 'suspicious',
        details: 'Potential manipulation detected in facial regions'
      };

      // Deduct credits and record analysis
      await req.user.recordAnalysis(analysisResult.result, req.requiredCredits);

      res.json({
        success: true,
        message: 'Analysis completed successfully',
        data: analysisResult,
        remainingCredits: req.user.credits
      });
    } catch (error) {
      console.error('Deepfake detection error:', error);
      res.status(500).json({
        success: false,
        message: 'Analysis failed',
      });
    }
  }
);

/**
 * @desc    Upload and analyze plagiarism content
 * @route   POST /api/detection/plagiarism
 * @access  Private (requires auth + 2 credits)
 */
router.post('/plagiarism',
  authenticate,              // Must be logged in
  requireCredits(2),         // Must have at least 2 credits (plagiarism costs more)
  async (req, res) => {
    try {
      console.log('Authenticated user:', req.user.email);
      console.log('Credits available:', req.user.credits);
      
      // Your plagiarism detection logic here
      const analysisResult = {
        confidence: 92.3,
        result: 'authentic',
        plagiarismPercentage: 3.2,
        sources: []
      };

      // Deduct credits and record analysis
      await req.user.recordAnalysis(analysisResult.result, req.requiredCredits);

      res.json({
        success: true,
        message: 'Plagiarism analysis completed successfully',
        data: analysisResult,
        remainingCredits: req.user.credits
      });
    } catch (error) {
      console.error('Plagiarism detection error:', error);
      res.status(500).json({
        success: false,
        message: 'Plagiarism analysis failed',
      });
    }
  }
);

/**
 * @desc    Get user's analysis history
 * @route   GET /api/detection/history
 * @access  Private
 */
router.get('/history',
  authenticate,
  async (req, res) => {
    try {
      // You can expand this to get actual analysis records from a separate collection
      const stats = req.user.getDashboardStats();
      
      res.json({
        success: true,
        data: {
          stats,
          recentAnalyses: [], // You can populate this from an analyses collection
        }
      });
    } catch (error) {
      console.error('History fetch error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch analysis history',
      });
    }
  }
);

/**
 * @desc    Get dashboard data
 * @route   GET /api/user/dashboard
 * @access  Private
 */
router.get('/dashboard',
  authenticate,
  async (req, res) => {
    try {
      const stats = req.user.getDashboardStats();
      
      res.json({
        success: true,
        data: {
          user: {
            name: req.user.fullName,
            email: req.user.email,
            plan: req.user.plan,
            joinDate: req.user.createdAt,
          },
          stats,
          credits: {
            remaining: req.user.credits,
            used: req.user.totalCreditsUsed,
            total: req.user.credits + req.user.totalCreditsUsed,
          }
        }
      });
    } catch (error) {
      console.error('Dashboard data error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch dashboard data',
      });
    }
  }
);

// ============================================
// ADMIN ONLY ROUTES
// ============================================

/**
 * @desc    Get all users (admin only)
 * @route   GET /api/admin/users
 * @access  Private/Admin
 */
router.get('/admin/users',
  ...adminOnly, // Spread the array: [authenticate, authorize('admin')]
  async (req, res) => {
    try {
      const users = await User.find({ isActive: true })
        .select('-password -refreshToken')
        .sort({ createdAt: -1 });
      
      res.json({
        success: true,
        data: users,
        count: users.length
      });
    } catch (error) {
      console.error('Admin users fetch error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch users',
      });
    }
  }
);

// ============================================
// PUBLIC ROUTES (NO AUTHENTICATION REQUIRED)
// ============================================

/**
 * @desc    Get service status/health
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
    }
  });
});

module.exports = router;