const express = require('express');
const router = express.Router();
const {
  getAllUsers,
  getUserById,
  updateProfile,
  changePassword,
  toggleUserStatus,
  deleteUser,
  getNotifications,
  markAllNotificationsRead,
  getActivityLogs,
} = require('../controllers/user.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { requireAdmin } = require('../middleware/admin.middleware');

router.use(authenticate);

router.get('/notifications', getNotifications);
router.put('/notifications/read-all', markAllNotificationsRead);
router.put('/profile', updateProfile);
router.put('/change-password', changePassword);
router.get('/:id', getUserById);

// Admin routes
router.get('/', requireAdmin, getAllUsers);
router.get('/admin/logs', requireAdmin, getActivityLogs);
router.put('/:id/toggle-status', requireAdmin, toggleUserStatus);
router.delete('/:id', requireAdmin, deleteUser);

module.exports = router;
