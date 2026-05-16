/**
 * realScanner.js
 *
 * Performs actual passive HTTP-based security checks against the target URL.
 * Uses Node 18+ built-in fetch. All checks are non-destructive (read-only GET/HEAD).
 */

const logger = require('../utils/logger');

// Security header checks — each missing header is a real finding
const HEADER_CHECKS = [
  {
    header: 'content-security-policy',
    type: 'Missing Security Header',
    severity: 'medium',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    title: 'Missing Content Security Policy (CSP) Header',
    description:
      'The Content-Security-Policy header is absent. Without CSP, the browser allows loading resources from any origin and executing inline scripts, significantly increasing the XSS attack surface.',
    recommendation:
      "Add a Content-Security-Policy header. A safe starting point: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      'https://owasp.org/www-project-secure-headers/',
    ],
  },
  {
    header: 'strict-transport-security',
    type: 'Missing HSTS Header',
    severity: 'high',
    cvssScore: 7.4,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    title: 'Missing HTTP Strict Transport Security (HSTS)',
    description:
      'The Strict-Transport-Security header is absent. Without HSTS, browsers may establish plain HTTP connections, exposing users to man-in-the-middle attacks and SSL stripping.',
    recommendation:
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — to all HTTPS responses.",
    cweId: 'CWE-319',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    ],
  },
  {
    header: 'x-frame-options',
    type: 'Clickjacking Vulnerability',
    severity: 'medium',
    cvssScore: 4.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
    description:
      'The X-Frame-Options header is not set. Attackers can embed this page in a hidden iframe to deceive users into performing unintended actions (clickjacking).',
    recommendation:
      "Add: X-Frame-Options: DENY — or use CSP with frame-ancestors 'none'.",
    cweId: 'CWE-1021',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: ['https://owasp.org/www-community/attacks/Clickjacking'],
  },
  {
    header: 'x-content-type-options',
    type: 'MIME Sniffing Vulnerability',
    severity: 'low',
    cvssScore: 3.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    title: 'Missing X-Content-Type-Options Header',
    description:
      'The X-Content-Type-Options header is missing. Browsers may MIME-sniff the response content type, potentially executing non-script files as scripts.',
    recommendation: 'Add: X-Content-Type-Options: nosniff — to all responses.',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    ],
  },
  {
    header: 'referrer-policy',
    type: 'Missing Referrer Policy',
    severity: 'info',
    cvssScore: 3.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    title: 'Missing Referrer-Policy Header',
    description:
      'The Referrer-Policy header is absent. Browsers may send sensitive URL information (including query parameters with tokens or IDs) to third-party sites via the Referer header.',
    recommendation:
      'Add: Referrer-Policy: strict-origin-when-cross-origin — or no-referrer for stricter control.',
    cweId: 'CWE-200',
    owaspCategory: 'A01:2021 - Broken Access Control',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
    ],
  },
  {
    header: 'permissions-policy',
    type: 'Missing Permissions Policy',
    severity: 'info',
    cvssScore: 2.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    title: 'Missing Permissions-Policy Header',
    description:
      'The Permissions-Policy header is absent. Without it, the browser grants unrestricted access to powerful APIs such as camera, microphone, and geolocation.',
    recommendation:
      'Add: Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=() — to restrict unnecessary browser API access.',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
    ],
  },
];

/**
 * Fetch a URL with a timeout. Returns { response, headersObj } or throws.
 */
const fetchWithTimeout = async (url, options = {}, timeoutMs = 12000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    const headersObj = {};
    response.headers.forEach((value, key) => {
      headersObj[key.toLowerCase()] = value;
    });
    return { response, headersObj };
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
};

/**
 * Main entry point. Returns an array of real vulnerability findings.
 * All checks are passive (GET/HEAD only — no exploit attempts).
 */
const performRealChecks = async (targetUrl) => {
  const findings = [];

  let url;
  try {
    url = new URL(targetUrl);
  } catch {
    logger.warn(`[RealScanner] Invalid URL: ${targetUrl}`);
    return findings;
  }

  // ── 1. Fetch the target ────────────────────────────────────────────────────
  let headersObj = {};
  let finalUrl = targetUrl;
  let statusCode = null;
  let reachable = false;

  try {
    const { response, headersObj: h } = await fetchWithTimeout(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'WebShield-Scanner/1.0 (Security Audit)',
        Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
      },
      redirect: 'follow',
    });
    headersObj = h;
    finalUrl = response.url || targetUrl;
    statusCode = response.status;
    reachable = true;
    logger.info(`[RealScanner] ${targetUrl} → ${statusCode} (${finalUrl})`);
  } catch (err) {
    const reason = err.name === 'AbortError' ? 'timed out' : err.message;
    logger.warn(`[RealScanner] Could not reach ${targetUrl}: ${reason}`);
    findings.push({
      type: 'Connectivity Issue',
      severity: 'info',
      cvssScore: 0,
      cvssVector: 'N/A',
      title: 'Target Unreachable During Real-Time Analysis',
      description: `WebShield could not connect to ${targetUrl} (${reason}). Passive vulnerability analysis based on common patterns has been applied instead.`,
      recommendation:
        'Ensure the target URL is publicly accessible and returns a valid HTTP response. Check DNS, firewall rules, and server status.',
      affectedEndpoint: targetUrl,
      evidence: reason,
      cweId: 'N/A',
      owaspCategory: 'N/A',
      references: [],
      isReal: false,
      exploitRisk: 'Info',
      tags: ['connectivity'],
    });
    return findings;
  }

  // ── 2. HTTPS enforcement ───────────────────────────────────────────────────
  const isHTTPS = finalUrl.startsWith('https://');

  if (!isHTTPS) {
    findings.push({
      type: 'Insecure Protocol',
      severity: 'critical',
      cvssScore: 9.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      title: 'Site Not Served Over HTTPS — Unencrypted Traffic',
      description:
        'The website is accessible over plain HTTP without TLS encryption. All data transmitted between the browser and server (including passwords, session tokens, and personal data) is exposed to interception and tampering by network attackers.',
      recommendation:
        "Obtain a free TLS certificate via Let's Encrypt (https://letsencrypt.org) and configure your server to serve all content over HTTPS. Add a 301 redirect from HTTP to HTTPS.",
      affectedEndpoint: targetUrl,
      evidence: `Target URL uses HTTP protocol — ${targetUrl}`,
      cweId: 'CWE-319',
      owaspCategory: 'A02:2021 - Cryptographic Failures',
      references: ['https://letsencrypt.org/', 'https://owasp.org/www-project-top-ten/'],
      isReal: true,
      exploitRisk: 'Critical',
      tags: ['CWE-319', 'A02:2021 - Cryptographic Failures', 'https', 'encryption'],
    });
  } else {
    // Check HTTP → HTTPS redirect
    try {
      const httpUrl = targetUrl.replace(/^https:\/\//i, 'http://');
      const { response: httpResp } = await fetchWithTimeout(
        httpUrl,
        {
          method: 'HEAD',
          redirect: 'manual',
          headers: { 'User-Agent': 'WebShield-Scanner/1.0' },
        },
        5000
      );
      const location = httpResp.headers.get('location') || '';
      const isRedirectToHttps = [301, 302, 307, 308].includes(httpResp.status) &&
        location.toLowerCase().startsWith('https://');

      if (!isRedirectToHttps) {
        findings.push({
          type: 'Missing HTTPS Redirect',
          severity: 'medium',
          cvssScore: 5.4,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
          title: 'HTTP to HTTPS Redirect Not Enforced',
          description:
            'The site does not automatically redirect HTTP requests to HTTPS. Users who visit the HTTP version are not protected by TLS encryption.',
          recommendation:
            'Configure your web server to return a 301 redirect from all http:// URLs to https://.',
          affectedEndpoint: httpUrl,
          evidence: `HTTP ${httpUrl} → status ${httpResp.status}, Location: ${location || 'none'}`,
          cweId: 'CWE-319',
          owaspCategory: 'A02:2021 - Cryptographic Failures',
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections'],
          isReal: true,
          exploitRisk: 'Medium',
          tags: ['CWE-319', 'A02:2021 - Cryptographic Failures', 'https'],
        });
      }
    } catch {
      // HTTP not accessible at all — probably fine
    }
  }

  // ── 3. Security headers ────────────────────────────────────────────────────
  for (const check of HEADER_CHECKS) {
    // Skip HSTS check for plain HTTP sites (it doesn't apply)
    if (check.header === 'strict-transport-security' && !isHTTPS) continue;

    if (!headersObj[check.header]) {
      findings.push({
        ...check,
        affectedEndpoint: finalUrl,
        evidence: `HTTP response from ${finalUrl} does not include the '${check.header}' header`,
        isReal: true,
        exploitRisk: check.severity.charAt(0).toUpperCase() + check.severity.slice(1),
        tags: [check.owaspCategory, check.cweId],
      });
    }
  }

  // ── 4. Server / technology version disclosure ──────────────────────────────
  const serverHeader = headersObj['server'];
  if (serverHeader && /[0-9]/.test(serverHeader)) {
    findings.push({
      type: 'Server Version Disclosure',
      severity: 'low',
      cvssScore: 3.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      title: 'Web Server Version Exposed in Response Headers',
      description: `The Server header discloses software and version (${serverHeader}). Attackers can use this to quickly identify known exploits for that exact version.`,
      recommendation:
        "Suppress or genericise the Server header. In Nginx: server_tokens off. In Apache: ServerTokens Prod. In Node/Express: app.disable('x-powered-by').",
      affectedEndpoint: finalUrl,
      evidence: `Server: ${serverHeader}`,
      cweId: 'CWE-200',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      references: ['https://owasp.org/www-project-web-security-testing-guide/'],
      isReal: true,
      exploitRisk: 'Low',
      tags: ['CWE-200', 'A05:2021 - Security Misconfiguration', 'information-disclosure'],
    });
  }

  const poweredBy = headersObj['x-powered-by'];
  if (poweredBy) {
    findings.push({
      type: 'Technology Disclosure',
      severity: 'low',
      cvssScore: 3.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      title: 'Backend Technology Disclosed via X-Powered-By Header',
      description: `The X-Powered-By header reveals the backend framework (${poweredBy}). This information assists attackers in targeting framework-specific vulnerabilities.`,
      recommendation:
        "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'). In PHP: set expose_php = Off in php.ini.",
      affectedEndpoint: finalUrl,
      evidence: `X-Powered-By: ${poweredBy}`,
      cweId: 'CWE-200',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      references: ['https://owasp.org/www-project-web-security-testing-guide/'],
      isReal: true,
      exploitRisk: 'Low',
      tags: ['CWE-200', 'A05:2021 - Security Misconfiguration', 'information-disclosure'],
    });
  }

  // ── 5. CORS misconfiguration ───────────────────────────────────────────────
  const corsOrigin = headersObj['access-control-allow-origin'];
  if (corsOrigin === '*') {
    findings.push({
      type: 'CORS Misconfiguration',
      severity: 'high',
      cvssScore: 7.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
      title: 'Wildcard CORS Policy Allows Any Origin',
      description:
        "The server returns Access-Control-Allow-Origin: * which permits any website to read the API response via JavaScript. If authenticated endpoints also use this policy, sensitive data is fully exposed to cross-site requests.",
      recommendation:
        'Replace the wildcard with an explicit allowlist of trusted origins. Never use * on authenticated or data-returning endpoints.',
      affectedEndpoint: finalUrl,
      evidence: 'Access-Control-Allow-Origin: *',
      cweId: 'CWE-942',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      references: ['https://owasp.org/www-community/attacks/CORS_Misconfiguration'],
      isReal: true,
      exploitRisk: 'High',
      tags: ['CWE-942', 'A05:2021 - Security Misconfiguration', 'cors'],
    });
  }

  // ── 6. Cookie security flags ───────────────────────────────────────────────
  const setCookie = headersObj['set-cookie'];
  if (setCookie) {
    const cookieLower = setCookie.toLowerCase();
    const issues = [];
    if (!cookieLower.includes('secure')) issues.push('Secure');
    if (!cookieLower.includes('httponly')) issues.push('HttpOnly');
    if (!cookieLower.includes('samesite')) issues.push('SameSite');

    if (issues.length > 0) {
      findings.push({
        type: 'Insecure Cookie Configuration',
        severity: 'medium',
        cvssScore: 4.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
        title: `Session Cookie Missing Security Flags: ${issues.join(', ')}`,
        description: `Cookies are set without critical security attributes: ${issues.join(', ')}. Missing Secure allows cookie transmission over HTTP (theft via MitM). Missing HttpOnly enables JavaScript access (XSS theft). Missing SameSite allows cross-site request forgery.`,
        recommendation:
          'Set all session cookies with: Secure; HttpOnly; SameSite=Strict (or Lax). Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600',
        affectedEndpoint: finalUrl,
        evidence: `Set-Cookie response missing: ${issues.join(', ')}`,
        cweId: 'CWE-614',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Security',
          'https://owasp.org/www-community/controls/SecureCookieAttribute',
        ],
        isReal: true,
        exploitRisk: 'Medium',
        tags: ['CWE-614', 'A02:2021 - Cryptographic Failures', 'cookies'],
      });
    }
  }

  // ── 7. robots.txt — check for sensitive path disclosure ───────────────────
  try {
    const robotsUrl = `${url.origin}/robots.txt`;
    const { response: robotsResp, headersObj: rh } = await fetchWithTimeout(
      robotsUrl,
      { method: 'GET', headers: { 'User-Agent': 'WebShield-Scanner/1.0' } },
      5000
    );

    if (robotsResp.status === 200) {
      const text = await robotsResp.text();
      const sensitivePatterns = [
        /\/admin/i, /\/backup/i, /\/config/i, /\/\.env/i,
        /\/database/i, /\/private/i, /\/secret/i, /\/internal/i,
      ];
      const matched = sensitivePatterns
        .map((p) => (text.match(p) ? text.match(p)[0] : null))
        .filter(Boolean);

      if (matched.length > 0) {
        findings.push({
          type: 'Sensitive Path Disclosure',
          severity: 'low',
          cvssScore: 3.7,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
          title: 'Sensitive Paths Disclosed in robots.txt',
          description: `The robots.txt file reveals sensitive directory or endpoint paths (${matched.join(', ')}) that should not be publicly documented. Although robots.txt is meant to guide crawlers, it effectively maps out restricted areas for attackers.`,
          recommendation:
            'Remove sensitive paths from robots.txt. Protect sensitive endpoints with authentication rather than relying on robots.txt exclusion.',
          affectedEndpoint: robotsUrl,
          evidence: `robots.txt contains: ${matched.join(', ')}`,
          cweId: 'CWE-200',
          owaspCategory: 'A05:2021 - Security Misconfiguration',
          references: ['https://owasp.org/www-project-web-security-testing-guide/'],
          isReal: true,
          exploitRisk: 'Low',
          tags: ['CWE-200', 'information-disclosure', 'robots.txt'],
        });
      }
    }
  } catch {
    // robots.txt check failed — not critical
  }

  logger.info(`[RealScanner] Completed real checks on ${targetUrl} — ${findings.length} findings`);
  return findings;
};

module.exports = { performRealChecks };
