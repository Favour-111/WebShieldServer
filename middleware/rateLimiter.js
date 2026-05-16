const rateLimit = require('express-rate-limit');

// Skip CORS preflight requests — they are not real API calls
const skipOptions = (req) => req.method === 'OPTIONS' || process.env.NODE_ENV === 'test';

/**
 * General API rate limiter
 * 500 requests per 15 minutes — ample for a SPA that polls many endpoints
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 500,
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipOptions,
  message: { success: false, message: 'Too many requests. Please try again later.' },
  handler: (req, res, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
      retryAfter: '15 minutes',
    });
  },
});

/**
 * Auth rate limiter — prevents brute-force on login/register
 * 30 attempts per 15 minutes (was 10 — too aggressive for normal use)
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipOptions,
  message: {
    success: false,
    message: 'Too many authentication attempts. Please wait 15 minutes and try again.',
  },
  handler: (req, res, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
      retryAfter: '15 minutes',
    });
  },
});

/**
 * Scan creation limiter — 10 per minute per user
 */
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipOptions,
  message: {
    success: false,
    message: 'Too many scan requests. Please wait a moment before starting another scan.',
  },
  handler: (req, res, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
      retryAfter: '60 seconds',
    });
  },
});

module.exports = { apiLimiter, authLimiter, scanLimiter };

