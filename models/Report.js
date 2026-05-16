const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    scan: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan',
      required: true,
    },
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
    type: {
      type: String,
      enum: ['pdf', 'json', 'csv', 'html'],
      default: 'pdf',
    },
    summary: {
      riskScore: { type: Number, default: 0 },
      totalVulnerabilities: { type: Number, default: 0 },
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
    },
    recommendations: [{ type: String }],
    complianceStatus: {
      owasp: { type: Boolean, default: false },
      pci: { type: Boolean, default: false },
      gdpr: { type: Boolean, default: false },
    },
    generatedAt: {
      type: Date,
      default: Date.now,
    },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    },
  },
  {
    timestamps: true,
  }
);

reportSchema.index({ user: 1, createdAt: -1 });
reportSchema.index({ scan: 1 });

module.exports = mongoose.model('Report', reportSchema);
