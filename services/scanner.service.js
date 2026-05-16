const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const Notification = require('../models/Notification');
const logger = require('../utils/logger');
const { performRealChecks } = require('./realScanner');

// In-memory state for active scans
const activeScanStates = new Map();

// Vulnerability templates for realistic simulation
const VULNERABILITY_TEMPLATES = [
  {
    type: 'SQL Injection',
    severity: 'critical',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    title: 'SQL Injection Vulnerability Detected',
    description:
      'A SQL injection vulnerability was detected in the login form. User-supplied input is not properly sanitized before being included in SQL queries, allowing an attacker to manipulate database queries.',
    exploitRisk: 'Critical',
    recommendation:
      'Use parameterized queries or prepared statements. Implement input validation and use an ORM framework. Apply principle of least privilege to database accounts.',
    evidence: "Parameter 'id' is vulnerable: ' OR '1'='1' -- successfully manipulated query",
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html'],
  },
  {
    type: 'XSS',
    severity: 'high',
    cvssScore: 7.4,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
    title: 'Cross-Site Scripting (XSS) Vulnerability',
    description:
      'A reflected XSS vulnerability was found in the search parameter. Malicious scripts can be injected and executed in the victim\'s browser, leading to session hijacking, credential theft, or malware distribution.',
    exploitRisk: 'High',
    recommendation:
      'Implement output encoding for all user-controlled data. Use Content Security Policy (CSP) headers. Validate and sanitize all input on both client and server side.',
    evidence: "<script>alert('XSS')</script> executes in search parameter",
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  },
  {
    type: 'Missing Security Header',
    severity: 'medium',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    title: 'Missing Content Security Policy Header',
    description:
      'The application does not implement a Content Security Policy (CSP) header. Without CSP, the browser will execute any inline scripts and allow loading of resources from any origin, increasing XSS attack surface.',
    exploitRisk: 'Medium',
    recommendation:
      "Add 'Content-Security-Policy' header to all responses. Define trusted content sources explicitly. Use 'strict-dynamic' for script loading.",
    evidence: 'HTTP response headers missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
  },
  {
    type: 'CSRF',
    severity: 'high',
    cvssScore: 8.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    title: 'Cross-Site Request Forgery (CSRF) Vulnerability',
    description:
      'State-changing endpoints lack CSRF token validation. An attacker can craft malicious requests that execute actions on behalf of authenticated users without their knowledge.',
    exploitRisk: 'High',
    recommendation:
      'Implement CSRF tokens on all state-changing operations. Use SameSite cookie attribute. Verify Origin and Referer headers. Implement double-submit cookie pattern.',
    evidence: 'POST /api/user/settings accepts requests without CSRF token validation',
    cweId: 'CWE-352',
    owaspCategory: 'A01:2021 - Broken Access Control',
    references: ['https://owasp.org/www-community/attacks/csrf'],
  },
  {
    type: 'Insecure Cookie',
    severity: 'medium',
    cvssScore: 4.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
    title: 'Session Cookie Missing Secure Flags',
    description:
      'Session cookies are set without the Secure, HttpOnly, and SameSite attributes. This allows potential interception of cookies over non-HTTPS connections and access via JavaScript.',
    exploitRisk: 'Medium',
    recommendation:
      'Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies. Ensure cookies are only transmitted over HTTPS.',
    evidence: "Set-Cookie: session=abc123; Path=/ (missing Secure, HttpOnly, SameSite flags)",
    cweId: 'CWE-614',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
  },
  {
    type: 'Sensitive Data Exposure',
    severity: 'critical',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    title: 'Sensitive Data Exposed in API Response',
    description:
      'API endpoints are returning sensitive information including password hashes, internal tokens, and PII data. This data should not be included in API responses.',
    exploitRisk: 'Critical',
    recommendation:
      'Review all API responses and remove sensitive fields. Implement response filtering. Use allowlists for API response fields. Apply data masking for sensitive information.',
    evidence: 'API /api/users returns password_hash, internal_token, and SSN fields',
    cweId: 'CWE-200',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    references: ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'],
  },
  {
    type: 'Directory Traversal',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    title: 'Path Traversal Vulnerability',
    description:
      'The file download endpoint is vulnerable to path traversal attacks. An attacker can access files outside the intended directory by manipulating the file path parameter.',
    exploitRisk: 'High',
    recommendation:
      'Validate and sanitize all file path inputs. Use a whitelist of allowed files. Resolve canonical paths and verify they are within allowed directories.',
    evidence: '/download?file=../../etc/passwd returns sensitive system files',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
  },
  {
    type: 'Clickjacking',
    severity: 'low',
    cvssScore: 3.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N',
    title: 'Clickjacking Vulnerability',
    description:
      'The application is missing X-Frame-Options and frame-ancestors CSP directive, allowing it to be embedded in malicious iframes. Attackers can trick users into clicking on invisible interface elements.',
    exploitRisk: 'Low',
    recommendation:
      "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header. Add frame-ancestors directive to Content-Security-Policy.",
    evidence: 'HTTP response missing X-Frame-Options header; page can be framed',
    cweId: 'CWE-1021',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: ['https://owasp.org/www-community/attacks/Clickjacking'],
  },
  {
    type: 'Open Port',
    severity: 'medium',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    title: 'Unnecessary Ports Exposed',
    description:
      'Multiple unnecessary ports are open and accessible from the internet. Port 8080 (development server), 27017 (MongoDB), and 6379 (Redis) are accessible without authentication.',
    exploitRisk: 'Medium',
    recommendation:
      'Close all unnecessary ports. Restrict database ports to localhost only. Implement firewall rules to limit access to production services.',
    evidence: 'Open ports: 8080 (HTTP-Alt), 27017 (MongoDB), 6379 (Redis)',
    cweId: 'CWE-284',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
  },
  {
    type: 'Weak Authentication',
    severity: 'high',
    cvssScore: 8.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    title: 'Weak Password Policy & No Brute Force Protection',
    description:
      'The authentication system accepts weak passwords (3+ characters), has no account lockout policy, and does not implement rate limiting on login attempts. Brute force attacks can easily compromise accounts.',
    exploitRisk: 'High',
    recommendation:
      'Enforce strong password policy (12+ chars, complexity requirements). Implement account lockout after 5 failed attempts. Add rate limiting and CAPTCHA. Consider MFA.',
    evidence: 'Password "abc" accepted; 1000 login attempts in 60 seconds not blocked',
    cweId: 'CWE-521',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    references: ['https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication'],
  },
];

// Simulated scan phases
const SCAN_PHASES = [
  { name: 'Initializing scanner', duration: 800 },
  { name: 'DNS resolution', duration: 600 },
  { name: 'Port enumeration', duration: 1200 },
  { name: 'SSL/TLS analysis', duration: 900 },
  { name: 'HTTP header analysis', duration: 700 },
  { name: 'Crawling target URL', duration: 1500 },
  { name: 'Testing SQL injection', duration: 2000 },
  { name: 'Testing XSS vulnerabilities', duration: 1800 },
  { name: 'CSRF validation checks', duration: 1000 },
  { name: 'Authentication security', duration: 1200 },
  { name: 'Cookie security analysis', duration: 800 },
  { name: 'Directory traversal tests', duration: 1100 },
  { name: 'Sensitive data exposure', duration: 900 },
  { name: 'Clickjacking assessment', duration: 600 },
  { name: 'Compiling results', duration: 1000 },
];

let io = null;

const setSocketIO = (socketInstance) => {
  io = socketInstance;
};

const emitToUser = (userId, event, data) => {
  if (io) {
    io.to(`user_${userId}`).emit(event, data);
  }
};

const startScan = async (scanId, userId) => {
  const stateKey = scanId.toString();
  activeScanStates.set(stateKey, { paused: false, stopped: false });

  try {
    const scan = await Scan.findById(scanId);
    if (!scan) return;

    scan.status = 'running';
    scan.startedAt = new Date();
    scan.progress = 0;
    await scan.save();

    emitToUser(userId, 'scan:started', { scanId: stateKey, targetUrl: scan.targetUrl });

    // ── Kick off real HTTP checks in parallel with phase 1 ─────────────────
    const realCheckPromise = performRealChecks(scan.targetUrl).catch((err) => {
      logger.warn(`[Scanner] Real checks failed: ${err.message}`);
      return [];
    });

    const totalPhases = SCAN_PHASES.length;
    let currentProgress = 0;

    // Phases 0-4 = setup/recon (real findings injected here)
    // Phases 5-13 = attack simulation (simulated findings)
    const REAL_INJECT_PHASE = 3; // inject real findings during "HTTP header analysis"

    for (let i = 0; i < totalPhases; i++) {
      const state = activeScanStates.get(stateKey);
      if (!state || state.stopped) {
        logger.info(`Scan ${stateKey} was stopped`);
        return;
      }

      // Wait while paused
      while (state.paused) {
        await sleep(500);
        const freshState = activeScanStates.get(stateKey);
        if (!freshState || freshState.stopped) return;
      }

      const phase = SCAN_PHASES[i];
      currentProgress = Math.round(((i + 1) / totalPhases) * 100);

      emitToUser(userId, 'scan:progress', {
        scanId: stateKey,
        progress: currentProgress,
        phase: phase.name,
        phaseIndex: i + 1,
        totalPhases,
      });

      await Scan.findByIdAndUpdate(scanId, { progress: currentProgress });

      // ── Inject real findings during the header-analysis phase ─────────────
      if (i === REAL_INJECT_PHASE) {
        const realFindings = await realCheckPromise;
        for (const finding of realFindings) {
          const state = activeScanStates.get(stateKey);
          if (!state || state.stopped) return;

          // Avoid duplicating a finding type already found
          const alreadyFound = await Vulnerability.exists({ scan: scanId, type: finding.type });
          if (alreadyFound) continue;

          const vuln = await Vulnerability.create({
            scan: scanId,
            user: userId,
            ...finding,
            affectedEndpoint: finding.affectedEndpoint || scan.targetUrl,
            tags: finding.tags || [finding.owaspCategory, finding.cweId].filter(Boolean),
          });

          emitToUser(userId, 'scan:vulnerability', { scanId: stateKey, vulnerability: vuln });
          await sleep(300); // brief pause between emits for visual effect
        }
      }

      // ── Simulated findings for deeper scan phases ─────────────────────────
      if (i >= 6 && i <= 13) {
        await maybeDiscoverVulnerability(scanId, userId, scan.targetUrl, stateKey);
      }

      await sleep(phase.duration);
    }

    // Finalize scan
    const finalState = activeScanStates.get(stateKey);
    if (!finalState || finalState.stopped) return;

    const vulnerabilities = await Vulnerability.find({ scan: scanId });
    const summary = computeSummary(vulnerabilities);
    const riskScore = computeRiskScore(summary);

    const completedAt = new Date();
    const startedAt = scan.startedAt;
    const duration = Math.round((completedAt - startedAt) / 1000);

    await Scan.findByIdAndUpdate(scanId, {
      status: 'completed',
      progress: 100,
      completedAt,
      duration,
      summary,
      riskScore,
    });

    // Create notification
    await Notification.create({
      user: userId,
      title: 'Scan Completed',
      message: `Scan of ${scan.targetUrl} completed. Found ${summary.total} vulnerabilities (${summary.critical} critical).`,
      type: 'scan_complete',
      severity: summary.critical > 0 ? 'critical' : summary.high > 0 ? 'high' : 'info',
      relatedResource: 'scan',
      relatedId: scanId,
    });

    emitToUser(userId, 'scan:completed', {
      scanId: stateKey,
      summary,
      riskScore,
      duration,
    });

    activeScanStates.delete(stateKey);
    logger.info(`Scan ${stateKey} completed. ${summary.total} vulnerabilities found.`);
  } catch (error) {
    logger.error(`Scan ${stateKey} error: ${error.message}`);
    await Scan.findByIdAndUpdate(scanId, { status: 'failed', errorMessage: error.message });
    emitToUser(userId, 'scan:error', { scanId: stateKey, error: error.message });
    activeScanStates.delete(stateKey);
  }
};

const maybeDiscoverVulnerability = async (scanId, userId, targetUrl, stateKey) => {
  // 40% chance to find a vulnerability per eligible phase
  if (Math.random() > 0.4) return;

  const scan = await Scan.findById(scanId);
  if (!scan) return;

  // Get a template not already used
  const usedTypes = await Vulnerability.distinct('type', { scan: scanId });
  const availableTemplates = VULNERABILITY_TEMPLATES.filter((t) => !usedTypes.includes(t.type));
  if (availableTemplates.length === 0) return;

  const template = availableTemplates[Math.floor(Math.random() * availableTemplates.length)];

  // Build affected endpoint from target URL
  const endpointSuffixes = ['/login', '/search', '/api/users', '/upload', '/download', '/admin', '/profile', '/'];
  const affectedEndpoint =
    targetUrl.replace(/\/$/, '') + endpointSuffixes[Math.floor(Math.random() * endpointSuffixes.length)];

  const vuln = await Vulnerability.create({
    scan: scanId,
    user: userId,
    ...template,
    affectedEndpoint,
    tags: [template.owaspCategory, template.cweId],
  });

  emitToUser(userId, 'scan:vulnerability', {
    scanId: stateKey,
    vulnerability: vuln,
  });
};

const pauseScan = (scanId) => {
  const state = activeScanStates.get(scanId);
  if (state) state.paused = true;
};

const resumeScan = (scanId) => {
  const state = activeScanStates.get(scanId);
  if (state) state.paused = false;
};

const stopScan = (scanId) => {
  const state = activeScanStates.get(scanId);
  if (state) {
    state.stopped = true;
    activeScanStates.delete(scanId);
  }
};

const computeSummary = (vulnerabilities) => {
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulnerabilities.forEach((v) => {
    summary.total++;
    if (summary[v.severity] !== undefined) summary[v.severity]++;
  });
  return summary;
};

const computeRiskScore = (summary) => {
  const score =
    summary.critical * 25 +
    summary.high * 15 +
    summary.medium * 8 +
    summary.low * 3 +
    summary.info * 1;
  return Math.min(100, score);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

module.exports = { startScan, pauseScan, resumeScan, stopScan, setSocketIO };
