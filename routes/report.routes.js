const express = require('express');
const router = express.Router();
const { generateReport, getReports, getReportById, deleteReport } = require('../controllers/report.controller');
const { authenticate } = require('../middleware/auth.middleware');

router.use(authenticate);

router.post('/generate/:scanId', generateReport);
router.get('/', getReports);
router.get('/:id', getReportById);
router.delete('/:id', deleteReport);

module.exports = router;
