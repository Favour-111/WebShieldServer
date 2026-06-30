const mongoose = require('mongoose');
const connectDB = require('../config/db');
const logger = require('../utils/logger');

const databaseReady = async (req, res, next) => {
  try {
    if (!process.env.MONGO_URI) {
      return res.status(503).json({
        success: false,
        message: 'Database connection is not configured on the server.',
      });
    }

    if (mongoose.connection.readyState === 1) {
      return next();
    }

    await connectDB();
    return next();
  } catch (error) {
    logger.error(`Database readiness check failed: ${error.message}`);
    return res.status(503).json({
      success: false,
      message: 'Database is temporarily unavailable. Please try again later.',
    });
  }
};

module.exports = { databaseReady };
