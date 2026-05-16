const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const Log = require('../models/Log');
const logger = require('../utils/logger');

/**
 * Generate JWT access token
 */
const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

/**
 * Generate JWT refresh token
 */
const generateRefreshToken = (id) =>
  jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  });

/**
 * @route   POST /api/auth/register
 */
const register = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'Email already registered.' });
    }

    const user = await User.create({ name, email, password });

    await Log.create({
      user: user._id,
      action: 'USER_REGISTER',
      resource: 'auth',
      level: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });

    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    user.loginCount += 1;
    await user.save({ validateBeforeSave: false });

    res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      token,
      refreshToken,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
        settings: user.settings,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/auth/login
 */
const login = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Account is deactivated.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await Log.create({
        user: user._id,
        action: 'LOGIN_FAILED',
        resource: 'auth',
        level: 'warn',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    user.loginCount += 1;
    await user.save({ validateBeforeSave: false });

    await Log.create({
      user: user._id,
      action: 'USER_LOGIN',
      resource: 'auth',
      level: 'success',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });

    res.json({
      success: true,
      message: 'Login successful.',
      token,
      refreshToken,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
        settings: user.settings,
        lastLogin: user.lastLogin,
        scanCount: user.scanCount,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   POST /api/auth/refresh
 */
const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;
    if (!token) {
      return res.status(401).json({ success: false, message: 'Refresh token required.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id).select('+refreshToken');

    if (!user || user.refreshToken !== token) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token.' });
    }

    const newToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save({ validateBeforeSave: false });

    res.json({ success: true, token: newToken, refreshToken: newRefreshToken });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token.' });
    }
    next(error);
  }
};

/**
 * @route   POST /api/auth/logout
 */
const logout = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (user) {
      user.refreshToken = undefined;
      await user.save({ validateBeforeSave: false });
    }

    await Log.create({
      user: req.user._id,
      action: 'USER_LOGOUT',
      resource: 'auth',
      level: 'info',
      ipAddress: req.ip,
    });

    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/auth/me
 */
const getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({ success: true, user });
  } catch (error) {
    next(error);
  }
};

module.exports = { register, login, refreshToken, logout, getMe };
