const User = require('../models/User');
const Scan = require('../models/Scan');
const Log = require('../models/Log');
const Notification = require('../models/Notification');
const logger = require('../utils/logger');

/**
 * @route   GET /api/users (admin)
 */
const getAllUsers = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    const role = req.query.role || '';

    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }
    if (role) query.role = role;

    const [users, total] = await Promise.all([
      User.find(query).select('-password -refreshToken').skip(skip).limit(limit).sort({ createdAt: -1 }),
      User.countDocuments(query),
    ]);

    res.json({
      success: true,
      users,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users/:id (admin or self)
 */
const getUserById = async (req, res, next) => {
  try {
    const targetId = req.params.id === 'me' ? req.user._id : req.params.id;

    if (req.user.role !== 'admin' && targetId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    const user = await User.findById(targetId).select('-password -refreshToken');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    res.json({ success: true, user });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/users/profile
 */
const updateProfile = async (req, res, next) => {
  try {
    const allowedFields = ['name', 'avatar', 'settings'];
    const updates = {};

    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    });

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -refreshToken');

    res.json({ success: true, message: 'Profile updated.', user });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/users/change-password
 */
const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id).select('+password');
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    }

    user.password = newPassword;
    await user.save();

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/users/:id/toggle-status (admin)
 */
const toggleUserStatus = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot modify your own account status.' });
    }

    user.isActive = !user.isActive;
    await user.save({ validateBeforeSave: false });

    await Log.create({
      user: req.user._id,
      action: user.isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
      resource: 'user',
      resourceId: user._id.toString(),
      level: 'warn',
      ipAddress: req.ip,
    });

    res.json({ success: true, message: `User ${user.isActive ? 'activated' : 'deactivated'}.`, user });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   DELETE /api/users/:id (admin)
 */
const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot delete your own account.' });
    }

    await User.findByIdAndDelete(req.params.id);

    await Log.create({
      user: req.user._id,
      action: 'USER_DELETED',
      resource: 'user',
      resourceId: req.params.id,
      level: 'warn',
      ipAddress: req.ip,
    });

    res.json({ success: true, message: 'User deleted successfully.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users/notifications
 */
const getNotifications = async (req, res, next) => {
  try {
    const notifications = await Notification.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);

    const unreadCount = await Notification.countDocuments({
      user: req.user._id,
      isRead: false,
    });

    res.json({ success: true, notifications, unreadCount });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   PUT /api/users/notifications/read-all
 */
const markAllNotificationsRead = async (req, res, next) => {
  try {
    await Notification.updateMany({ user: req.user._id, isRead: false }, { isRead: true });
    res.json({ success: true, message: 'All notifications marked as read.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route   GET /api/users/activity-logs (admin)
 */
const getActivityLogs = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      Log.find({}).populate('user', 'name email').sort({ createdAt: -1 }).skip(skip).limit(limit),
      Log.countDocuments(),
    ]);

    res.json({
      success: true,
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getAllUsers,
  getUserById,
  updateProfile,
  changePassword,
  toggleUserStatus,
  deleteUser,
  getNotifications,
  markAllNotificationsRead,
  getActivityLogs,
};
