const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const User = require('../models/User');
const Log = require('../models/Log');

/**
 * @route   GET /api/dashboard/stats
 */
const getDashboardStats = async (req, res, next) => {
  try {
    const userId = req.user._id;

    const [
      totalScans,
      activeScans,
      completedScans,
      totalVulns,
      criticalVulns,
      highVulns,
      mediumVulns,
      lowVulns,
      recentScans,
    ] = await Promise.all([
      Scan.countDocuments({ user: userId }),
      Scan.countDocuments({ user: userId, status: 'running' }),
      Scan.countDocuments({ user: userId, status: 'completed' }),
      Vulnerability.countDocuments({ user: userId }),
      Vulnerability.countDocuments({ user: userId, severity: 'critical' }),
      Vulnerability.countDocuments({ user: userId, severity: 'high' }),
      Vulnerability.countDocuments({ user: userId, severity: 'medium' }),
      Vulnerability.countDocuments({ user: userId, severity: 'low' }),
      Scan.find({ user: userId }).sort({ createdAt: -1 }).limit(5),
    ]);

    const successRate =
      totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0;

    res.json({
      success: true,
      stats: {
        totalScans,
        activeScans,
        completedScans,
        totalVulnerabilities: totalVulns,
        critical: criticalVulns,
        high: highVulns,
        medium: mediumVulns,
        low: lowVulns,
        successRate,
      },
      recentScans,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/dashboard/trend
 * Vulnerability trend over last 30 days
 */
const getVulnerabilityTrend = async (req, res, next) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const since = new Date();
    since.setDate(since.getDate() - days);

    const trend = await Vulnerability.aggregate([
      {
        $match: {
          user: req.user._id,
          createdAt: { $gte: since },
        },
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            severity: '$severity',
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.date': 1 } },
    ]);

    res.json({ success: true, trend });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/dashboard/admin-stats (admin)
 */
const getAdminStats = async (req, res, next) => {
  try {
    const [totalUsers, totalScans, totalVulns, activeScans, recentLogs] = await Promise.all([
      User.countDocuments(),
      Scan.countDocuments(),
      Vulnerability.countDocuments(),
      Scan.countDocuments({ status: 'running' }),
      Log.find({}).populate('user', 'name email').sort({ createdAt: -1 }).limit(20),
    ]);

    const userGrowth = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: -1 } },
      { $limit: 30 },
    ]);

    const scansByStatus = await Scan.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]);

    res.json({
      success: true,
      stats: {
        totalUsers,
        totalScans,
        totalVulnerabilities: totalVulns,
        activeScans,
      },
      userGrowth,
      scansByStatus,
      recentLogs,
    });
  } catch (error) {
    next(error);
  }
};

module.exports = { getDashboardStats, getVulnerabilityTrend, getAdminStats };
