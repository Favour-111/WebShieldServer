const Report = require('../models/Report');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');

/**
 * @route   POST /api/reports/generate/:scanId
 */
const generateReport = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.scanId).populate('vulnerabilities');

    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });
    if (scan.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    if (scan.status !== 'completed') {
      return res.status(400).json({ success: false, message: 'Scan must be completed before generating a report.' });
    }

    const recommendations = [
      'Immediately patch all critical SQL Injection vulnerabilities',
      'Implement Content Security Policy (CSP) headers to prevent XSS',
      'Enable CSRF protection on all state-changing endpoints',
      'Close unnecessary open ports and restrict firewall rules',
      'Implement HTTPS and HSTS security headers',
      'Use parameterized queries for all database interactions',
      'Implement proper input validation and output encoding',
      'Enable rate limiting on authentication endpoints',
      'Regular security audits and penetration testing',
      'Keep all software dependencies up-to-date',
    ];

    const report = await Report.create({
      scan: scan._id,
      user: req.user._id,
      title: `Security Report - ${scan.scanName || scan.targetUrl}`,
      summary: {
        riskScore: scan.riskScore,
        totalVulnerabilities: scan.summary.total,
        critical: scan.summary.critical,
        high: scan.summary.high,
        medium: scan.summary.medium,
        low: scan.summary.low,
        info: scan.summary.info,
      },
      recommendations: recommendations.slice(0, 5),
      complianceStatus: {
        owasp: scan.summary.critical === 0 && scan.summary.high === 0,
        pci: scan.summary.critical === 0,
        gdpr: scan.summary.critical === 0,
      },
    });

    scan.reportGenerated = true;
    await scan.save();

    res.status(201).json({ success: true, message: 'Report generated.', report });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/reports
 */
const getReports = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const [reports, total] = await Promise.all([
      Report.find({ user: req.user._id })
        .populate('scan', 'targetUrl scanName status')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Report.countDocuments({ user: req.user._id }),
    ]);

    res.json({
      success: true,
      reports,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/reports/:id
 */
const getReportById = async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate({
        path: 'scan',
        populate: { path: 'vulnerabilities' },
      });

    if (!report) return res.status(404).json({ success: false, message: 'Report not found.' });
    if (report.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    res.json({ success: true, report });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/reports/:id
 */
const deleteReport = async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ success: false, message: 'Report not found.' });
    if (report.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    await Report.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Report deleted.' });
  } catch (error) {
    next(error);
  }
};

module.exports = { generateReport, getReports, getReportById, deleteReport };
