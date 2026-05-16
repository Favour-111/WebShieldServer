require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const Report = require('../models/Report');
const Notification = require('../models/Notification');

const connectDB = async () => {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/webshield');
  console.log('✓ MongoDB connected');
};

const seedData = async () => {
  await connectDB();

  console.log('🌱 Seeding WebShield Scanner database...');

  // Clear existing data
  await Promise.all([
    User.deleteMany({}),
    Scan.deleteMany({}),
    Vulnerability.deleteMany({}),
    Report.deleteMany({}),
    Notification.deleteMany({}),
  ]);

  console.log('✓ Cleared existing data');

  // Create admin user
  const admin = await User.create({
    name: 'Admin User',
    email: 'admin@webshield.io',
    password: 'Admin@1234',
    role: 'admin',
    isActive: true,
    isVerified: true,
    lastLogin: new Date(),
    loginCount: 42,
    scanCount: 15,
  });

  // Create regular user
  const user = await User.create({
    name: 'John Doe',
    email: 'john@example.com',
    password: 'User@1234',
    role: 'user',
    isActive: true,
    isVerified: true,
    lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000),
    loginCount: 12,
    scanCount: 8,
  });

  console.log('✓ Created users');

  // Create demo scans
  const scanTargets = [
    { url: 'https://example.com', name: 'Example.com Security Audit', status: 'completed', risk: 78 },
    { url: 'https://testphp.vulnweb.com', name: 'VulnWeb Assessment', status: 'completed', risk: 92 },
    { url: 'https://demo.testfire.net', name: 'Testfire Pen Test', status: 'completed', risk: 65 },
    { url: 'https://juice-shop.herokuapp.com', name: 'OWASP Juice Shop', status: 'running', risk: 45 },
    { url: 'https://hackthissite.org', name: 'HackThisSite Audit', status: 'completed', risk: 55 },
  ];

  const scans = [];
  for (const target of scanTargets) {
    const startedAt = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000);
    const completedAt = new Date(startedAt.getTime() + Math.random() * 300 * 1000 + 60000);

    const scan = await Scan.create({
      user: user._id,
      targetUrl: target.url,
      scanName: target.name,
      status: target.status,
      progress: target.status === 'completed' ? 100 : Math.floor(Math.random() * 60 + 20),
      scanType: 'standard',
      startedAt,
      completedAt: target.status === 'completed' ? completedAt : null,
      duration: target.status === 'completed' ? Math.floor((completedAt - startedAt) / 1000) : 0,
      riskScore: target.risk,
      summary: {
        total: Math.floor(Math.random() * 8 + 3),
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 3 + 1),
        medium: Math.floor(Math.random() * 3 + 1),
        low: Math.floor(Math.random() * 2 + 1),
        info: Math.floor(Math.random() * 2),
      },
    });
    scans.push(scan);
  }

  console.log('✓ Created scans');

  // Create vulnerabilities for completed scans
  const vulnData = [
    { type: 'SQL Injection', severity: 'critical', cvssScore: 9.8, title: 'SQL Injection in Login Form' },
    { type: 'XSS', severity: 'high', cvssScore: 7.4, title: 'Reflected XSS in Search Parameter' },
    { type: 'Missing Security Header', severity: 'medium', cvssScore: 5.3, title: 'Missing Content-Security-Policy' },
    { type: 'CSRF', severity: 'high', cvssScore: 8.1, title: 'CSRF on Account Settings' },
    { type: 'Insecure Cookie', severity: 'medium', cvssScore: 4.3, title: 'Session Cookie Missing Secure Flag' },
    { type: 'Sensitive Data Exposure', severity: 'critical', cvssScore: 9.1, title: 'API Exposes Password Hashes' },
    { type: 'Directory Traversal', severity: 'high', cvssScore: 7.5, title: 'Path Traversal in File Download' },
    { type: 'Clickjacking', severity: 'low', cvssScore: 3.1, title: 'Missing X-Frame-Options Header' },
    { type: 'Open Port', severity: 'medium', cvssScore: 5.0, title: 'MongoDB Port Publicly Accessible' },
    { type: 'Weak Authentication', severity: 'high', cvssScore: 8.3, title: 'No Brute Force Protection' },
  ];

  for (const scan of scans.filter((s) => s.status === 'completed')) {
    const count = Math.floor(Math.random() * 5 + 2);
    const shuffled = [...vulnData].sort(() => Math.random() - 0.5).slice(0, count);

    for (const v of shuffled) {
      await Vulnerability.create({
        scan: scan._id,
        user: user._id,
        title: v.title,
        type: v.type,
        severity: v.severity,
        cvssScore: v.cvssScore,
        affectedEndpoint: scan.targetUrl + '/login',
        description: `A ${v.type} vulnerability was detected during the security assessment of ${scan.targetUrl}. This requires immediate remediation.`,
        exploitRisk: v.severity === 'critical' ? 'Critical' : v.severity === 'high' ? 'High' : 'Medium',
        recommendation: 'Apply security patches and follow OWASP remediation guidelines.',
        status: Math.random() > 0.7 ? 'resolved' : 'open',
        cweId: 'CWE-' + Math.floor(Math.random() * 900 + 1),
        owaspCategory: 'A0' + Math.floor(Math.random() * 9 + 1) + ':2021',
      });
    }
  }

  console.log('✓ Created vulnerabilities');

  // Create notifications
  await Notification.create([
    {
      user: user._id,
      title: 'Critical Vulnerability Found',
      message: 'SQL Injection detected on example.com - immediate action required',
      type: 'vulnerability_found',
      severity: 'critical',
    },
    {
      user: user._id,
      title: 'Scan Completed',
      message: 'Security scan of testphp.vulnweb.com completed with 9 findings',
      type: 'scan_complete',
      severity: 'high',
    },
    {
      user: user._id,
      title: 'Report Ready',
      message: 'Your security report for Example.com is ready to download',
      type: 'report_ready',
      severity: 'info',
      isRead: true,
    },
  ]);

  console.log('✓ Created notifications');
  console.log('\n🎉 Seed data created successfully!');
  console.log('\nAdmin credentials:');
  console.log('  Email:    admin@webshield.io');
  console.log('  Password: Admin@1234');
  console.log('\nUser credentials:');
  console.log('  Email:    john@example.com');
  console.log('  Password: User@1234');

  await mongoose.disconnect();
  process.exit(0);
};

seedData().catch((err) => {
  console.error('Seed error:', err);
  process.exit(1);
});
