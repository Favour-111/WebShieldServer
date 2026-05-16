const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    message: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      enum: ['scan_complete', 'vulnerability_found', 'report_ready', 'system', 'alert', 'info'],
      default: 'info',
    },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
      default: 'info',
    },
    isRead: {
      type: Boolean,
      default: false,
    },
    relatedResource: {
      type: String,
      default: '',
    },
    relatedId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

notificationSchema.index({ user: 1, isRead: 1 });
notificationSchema.index({ createdAt: -1 });

// Auto-expire notifications after 30 days
notificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

module.exports = mongoose.model('Notification', notificationSchema);
