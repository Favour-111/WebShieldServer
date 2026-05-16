const express = require('express');
const router = express.Router();
const {
  createScan,
  getScans,
  getScanById,
  pauseScan,
  resumeScan,
  stopScan,
  deleteScan,
  getAllScans,
} = require('../controllers/scan.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { requireAdmin } = require('../middleware/admin.middleware');
const { scanLimiter } = require('../middleware/rateLimiter');

router.use(authenticate);

router.post('/', scanLimiter, createScan);
router.get('/', getScans);
router.get('/admin/all', requireAdmin, getAllScans);
router.get('/:id', getScanById);
router.put('/:id/pause', pauseScan);
router.put('/:id/resume', resumeScan);
router.put('/:id/stop', stopScan);
router.delete('/:id', deleteScan);

module.exports = router;
