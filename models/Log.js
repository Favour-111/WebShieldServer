const mongoose = require('mongoose');

const logSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    action: {
      type: String,
      required: true,
      trim: true,
    },
    resource: {
      type: String,
      trim: true,
      default: '',
    },
    resourceId: {
      type: String,
      default: '',
    },
    level: {
      type: String,
      enum: ['info', 'warn', 'error', 'success'],
      default: 'info',
    },
    ipAddress: {
      type: String,
      default: '',
    },
    userAgent: {
      type: String,
      default: '',
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    status: {
      type: Number,
      default: 200,
    },
  },
  {
    timestamps: true,
  }
);

logSchema.index({ user: 1, createdAt: -1 });
logSchema.index({ action: 1 });
logSchema.index({ level: 1 });

// Auto-expire logs after 90 days
logSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7776000 });

module.exports = mongoose.model('Log', logSchema);
