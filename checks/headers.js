const axios = require('axios');

// Security headers to check and their descriptions
const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    description: 'מאלץ חיבורי HTTPS בלבד, מונע התקפות downgrade',
    severity: 'high',
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    description: 'מגן מפני XSS והזרקת קוד על ידי הגבלת מקורות תוכן',
    severity: 'high',
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'מונע MIME type sniffing - צריך להיות nosniff',
    severity: 'medium',
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'מגן מפני clickjacking על ידי חסימת הטמעה ב-iframe',
    severity: 'medium',
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    description: 'מפעיל סינון XSS מובנה בדפדפן (מיושן אך עדיין שימושי)',
    severity: 'low',
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'שולט בכמות מידע Referrer שנשלח בבקשות',
    severity: 'low',
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'שולט באילו תכונות דפדפן ו-APIs ניתן להשתמש',
    severity: 'medium',
  },
  'x-permitted-cross-domain-policies': {
    name: 'X-Permitted-Cross-Domain-Policies',
    description: 'שולט בגישה cross-domain עבור Flash ו-PDF',
    severity: 'low',
  },
  'cross-origin-opener-policy': {
    name: 'Cross-Origin-Opener-Policy',
    description: 'מבודד את הדף מחלונות cross-origin',
    severity: 'medium',
  },
  'cross-origin-resource-policy': {
    name: 'Cross-Origin-Resource-Policy',
    description: 'מגן על משאבים מטעינה cross-origin',
    severity: 'medium',
  },
};

async function runHeadersCheck(url) {
  const response = await axios.get(url, {
    timeout: 10000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      'User-Agent': 'SecurityTestingTool/1.0',
    },
  });

  const responseHeaders = response.headers;
  const results = [];
  let score = 0;
  const maxScore = Object.keys(SECURITY_HEADERS).length;

  for (const [header, info] of Object.entries(SECURITY_HEADERS)) {
    const value = responseHeaders[header];
    const present = !!value;
    if (present) score++;

    results.push({
      header: info.name,
      key: header,
      present,
      value: value || null,
      description: info.description,
      severity: info.severity,
    });
  }

  // Check for information disclosure headers
  const infoLeaks = [];
  const leakHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
  for (const h of leakHeaders) {
    if (responseHeaders[h]) {
      infoLeaks.push({ header: h, value: responseHeaders[h] });
    }
  }

  return {
    score: Math.round((score / maxScore) * 100),
    totalChecks: maxScore,
    passed: score,
    failed: maxScore - score,
    results,
    infoLeaks,
    statusCode: response.status,
  };
}

module.exports = { runHeadersCheck };
