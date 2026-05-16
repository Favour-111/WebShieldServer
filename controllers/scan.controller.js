const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const User = require('../models/User');
const Notification = require('../models/Notification');
const Log = require('../models/Log');
const scannerService = require('../services/scanner.service');
const logger = require('../utils/logger');

/**
 * @route   POST /api/scans
 */
const createScan = async (req, res, next) => {
  try {
    const { targetUrl, scanName, scanType, scanChecks } = req.body;

    // Basic URL validation
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).json({ success: false, message: 'URL must use HTTP or HTTPS protocol.' });
      }
    } catch {
      return res.status(400).json({ success: false, message: 'Invalid URL format.' });
    }

    const scan = await Scan.create({
      user: req.user._id,
      targetUrl: parsedUrl.toString(),
      scanName: scanName || `Scan - ${parsedUrl.hostname}`,
      scanType: scanType || 'standard',
      scanChecks: scanChecks || {},
      ipAddress: req.ip,
      status: 'queued',
    });

    await User.findByIdAndUpdate(req.user._id, { $inc: { scanCount: 1 } });

    await Log.create({
      user: req.user._id,
      action: 'SCAN_CREATED',
      resource: 'scan',
      resourceId: scan._id.toString(),
      level: 'info',
      ipAddress: req.ip,
    });

    // Start scan asynchronously
    scannerService.startScan(scan._id, req.user._id);

    res.status(201).json({ success: true, message: 'Scan started.', scan });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/scans
 */
const getScans = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const status = req.query.status || '';
    const search = req.query.search || '';

    const query = { user: req.user._id };
    if (status) query.status = status;
    if (search) {
      query.$or = [
        { targetUrl: { $regex: search, $options: 'i' } },
        { scanName: { $regex: search, $options: 'i' } },
      ];
    }

    const [scans, total] = await Promise.all([
      Scan.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
      Scan.countDocuments(query),
    ]);

    res.json({
      success: true,
      scans,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/scans/:id
 */
const getScanById = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id).populate('vulnerabilities');

    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });

    const isOwner = scan.user.toString() === req.user._id.toString();
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    res.json({ success: true, scan });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/scans/:id/pause
 */
const pauseScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });
    if (scan.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    if (scan.status !== 'running') {
      return res.status(400).json({ success: false, message: 'Only running scans can be paused.' });
    }

    scan.status = 'paused';
    await scan.save();
    scannerService.pauseScan(scan._id.toString());

    res.json({ success: true, message: 'Scan paused.', scan });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/scans/:id/resume
 */
const resumeScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });
    if (scan.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    if (scan.status !== 'paused') {
      return res.status(400).json({ success: false, message: 'Only paused scans can be resumed.' });
    }

    scan.status = 'running';
    await scan.save();
    scannerService.resumeScan(scan._id.toString());

    res.json({ success: true, message: 'Scan resumed.', scan });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/scans/:id/stop
 */
const stopScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });
    if (scan.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    scan.status = 'stopped';
    scan.completedAt = new Date();
    await scan.save();
    scannerService.stopScan(scan._id.toString());

    res.json({ success: true, message: 'Scan stopped.', scan });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/scans/:id
 */
const deleteScan = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found.' });

    const isOwner = scan.user.toString() === req.user._id.toString();
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    await Vulnerability.deleteMany({ scan: scan._id });
    await Scan.findByIdAndDelete(scan._id);

    res.json({ success: true, message: 'Scan deleted successfully.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/scans/admin/all (admin)
 */
const getAllScans = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find({}).populate('user', 'name email').sort({ createdAt: -1 }).skip(skip).limit(limit),
      Scan.countDocuments(),
    ]);

    res.json({
      success: true,
      scans,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = { createScan, getScans, getScanById, pauseScan, resumeScan, stopScan, deleteScan, getAllScans };
