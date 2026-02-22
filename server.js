const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { runHeadersCheck } = require('./checks/headers');
const { runSslCheck } = require('./checks/ssl');
const { runDnsCheck } = require('./checks/dns');
const { runTechDetection } = require('./checks/tech');
const { runPortCheck } = require('./checks/ports');
const { runMalwareCheck } = require('./checks/malware');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      fontSrc: ["'self'", 'fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS — same-origin app: allow all origins (rate limiting handles abuse)
app.use(cors({
  origin: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

// Rate limiting — max 20 scans per 10 minutes per IP
const scanLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'יותר מדי בקשות, נסה שוב בעוד 10 דקות' },
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Validate and normalize URL input
function normalizeUrl(input) {
  if (typeof input !== 'string') return null;
  let url = input.trim();
  if (url.length > 253) return null;
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const hostname = parsed.hostname;
    // Block private/internal IPs and hostnames (SSRF prevention)
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname) ||
      hostname === '0.0.0.0' ||
      hostname.endsWith('.local') ||
      hostname === 'metadata.google.internal' ||
      hostname.endsWith('.internal')
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

// Generic error response — no raw error messages exposed
function safeError(res, status, message) {
  res.status(status).json({ error: message });
}

// Full scan endpoint
app.post('/api/scan', scanLimiter, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return safeError(res, 400, 'URL is required');

  const parsed = normalizeUrl(url);
  if (!parsed) return safeError(res, 400, 'Invalid URL or blocked address');

  const targetUrl = parsed.href;
  const hostname = parsed.hostname;

  try {
    const [headers, ssl, dns, tech, ports, malware] = await Promise.allSettled([
      runHeadersCheck(targetUrl),
      runSslCheck(hostname),
      runDnsCheck(hostname),
      runTechDetection(targetUrl),
      runPortCheck(hostname),
      runMalwareCheck(targetUrl, hostname),
    ]);

    res.json({
      target: targetUrl,
      timestamp: new Date().toISOString(),
      headers: headers.status === 'fulfilled' ? headers.value : { error: 'Check failed' },
      ssl:     ssl.status     === 'fulfilled' ? ssl.value     : { error: 'Check failed' },
      dns:     dns.status     === 'fulfilled' ? dns.value     : { error: 'Check failed' },
      tech:    tech.status    === 'fulfilled' ? tech.value    : { error: 'Check failed' },
      ports:   ports.status   === 'fulfilled' ? ports.value   : { error: 'Check failed' },
      malware: malware.status === 'fulfilled' ? malware.value : { error: 'Check failed' },
    });
  } catch {
    safeError(res, 500, 'Scan failed');
  }
});

// Individual check endpoints
app.post('/api/check/headers', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runHeadersCheck(parsed.href)); } catch { safeError(res, 500, 'Check failed'); }
});

app.post('/api/check/ssl', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runSslCheck(parsed.hostname)); } catch { safeError(res, 500, 'Check failed'); }
});

app.post('/api/check/dns', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runDnsCheck(parsed.hostname)); } catch { safeError(res, 500, 'Check failed'); }
});

app.post('/api/check/tech', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runTechDetection(parsed.href)); } catch { safeError(res, 500, 'Check failed'); }
});

app.post('/api/check/ports', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runPortCheck(parsed.hostname)); } catch { safeError(res, 500, 'Check failed'); }
});

app.post('/api/check/malware', scanLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body?.url);
  if (!parsed) return safeError(res, 400, 'Invalid URL');
  try { res.json(await runMalwareCheck(parsed.href, parsed.hostname)); } catch { safeError(res, 500, 'Check failed'); }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`Security Testing Tool running on http://${HOST}:${PORT}`);
});
