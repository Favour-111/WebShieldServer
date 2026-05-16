const express = require('express');
const router = express.Router();
const { getDashboardStats, getVulnerabilityTrend, getAdminStats } = require('../controllers/dashboard.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { requireAdmin } = require('../middleware/admin.middleware');

router.use(authenticate);

router.get('/stats', getDashboardStats);
router.get('/trend', getVulnerabilityTrend);
router.get('/admin', requireAdmin, getAdminStats);

module.exports = router;
