const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    targetUrl: {
      type: String,
      required: [true, 'Target URL is required'],
      trim: true,
    },
    scanName: {
      type: String,
      trim: true,
      default: '',
    },
    status: {
      type: String,
      enum: ['queued', 'running', 'paused', 'completed', 'failed', 'stopped'],
      default: 'queued',
    },
    progress: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    scanType: {
      type: String,
      enum: ['quick', 'standard', 'deep', 'custom'],
      default: 'standard',
    },
    startedAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    duration: {
      type: Number,
      default: 0, // in seconds
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    summary: {
      total: { type: Number, default: 0 },
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
    },
    scanChecks: {
      sqlInjection: { type: Boolean, default: true },
      xss: { type: Boolean, default: true },
      csrf: { type: Boolean, default: true },
      openPorts: { type: Boolean, default: true },
      securityHeaders: { type: Boolean, default: true },
      weakAuth: { type: Boolean, default: true },
      directoryTraversal: { type: Boolean, default: true },
      clickjacking: { type: Boolean, default: true },
      insecureCookies: { type: Boolean, default: true },
      sensitiveData: { type: Boolean, default: true },
    },
    ipAddress: {
      type: String,
      default: '',
    },
    errorMessage: {
      type: String,
      default: '',
    },
    reportGenerated: {
      type: Boolean,
      default: false,
    },
    tags: [{ type: String }],
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual: vulnerabilities
scanSchema.virtual('vulnerabilities', {
  ref: 'Vulnerability',
  localField: '_id',
  foreignField: 'scan',
});

// Index for performance
scanSchema.index({ user: 1, createdAt: -1 });
scanSchema.index({ status: 1 });
scanSchema.index({ targetUrl: 1 });

module.exports = mongoose.model('Scan', scanSchema);
