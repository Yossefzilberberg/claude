const express = require('express');
const cors = require('cors');
const path = require('path');
const { runHeadersCheck } = require('./checks/headers');
const { runSslCheck } = require('./checks/ssl');
const { runDnsCheck } = require('./checks/dns');
const { runTechDetection } = require('./checks/tech');
const { runPortCheck } = require('./checks/ports');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Validate and normalize URL input
function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  try {
    const parsed = new URL(url);
    // Only allow http/https protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    // Block private/internal IPs to prevent SSRF
    const hostname = parsed.hostname;
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname) ||
      hostname === '0.0.0.0' ||
      hostname.endsWith('.local')
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

// Full scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  const parsed = normalizeUrl(url);
  if (!parsed) {
    return res.status(400).json({ error: 'Invalid URL or blocked address' });
  }

  const targetUrl = parsed.href;
  const hostname = parsed.hostname;

  try {
    const [headers, ssl, dns, tech, ports] = await Promise.allSettled([
      runHeadersCheck(targetUrl),
      runSslCheck(hostname),
      runDnsCheck(hostname),
      runTechDetection(targetUrl),
      runPortCheck(hostname),
    ]);

    const results = {
      target: targetUrl,
      timestamp: new Date().toISOString(),
      headers: headers.status === 'fulfilled' ? headers.value : { error: headers.reason?.message },
      ssl: ssl.status === 'fulfilled' ? ssl.value : { error: ssl.reason?.message },
      dns: dns.status === 'fulfilled' ? dns.value : { error: dns.reason?.message },
      tech: tech.status === 'fulfilled' ? tech.value : { error: tech.reason?.message },
      ports: ports.status === 'fulfilled' ? ports.value : { error: ports.reason?.message },
    };

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Scan failed: ' + err.message });
  }
});

// Individual check endpoints
app.post('/api/check/headers', async (req, res) => {
  const { url } = req.body;
  const parsed = normalizeUrl(url);
  if (!parsed) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await runHeadersCheck(parsed.href);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/check/ssl', async (req, res) => {
  const { url } = req.body;
  const parsed = normalizeUrl(url);
  if (!parsed) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await runSslCheck(parsed.hostname);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/check/dns', async (req, res) => {
  const { url } = req.body;
  const parsed = normalizeUrl(url);
  if (!parsed) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await runDnsCheck(parsed.hostname);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/check/tech', async (req, res) => {
  const { url } = req.body;
  const parsed = normalizeUrl(url);
  if (!parsed) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await runTechDetection(parsed.href);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/check/ports', async (req, res) => {
  const { url } = req.body;
  const parsed = normalizeUrl(url);
  if (!parsed) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await runPortCheck(parsed.hostname);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Security Testing Tool running on http://localhost:${PORT}`);
});
