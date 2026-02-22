const axios = require('axios');

// Technology detection patterns
const TECH_PATTERNS = {
  // JavaScript Frameworks
  'React': { header: null, body: ['react', '__NEXT_DATA__', '_next/', 'reactroot'], meta: ['next', 'gatsby'] },
  'Vue.js': { header: null, body: ['vue.js', 'vue.min.js', '__VUE__', 'nuxt', '__NUXT__'], meta: [] },
  'Angular': { header: null, body: ['ng-version', 'ng-app', 'angular.js', 'angular.min.js'], meta: [] },
  'jQuery': { header: null, body: ['jquery.js', 'jquery.min.js', 'jquery/'], meta: [] },
  'Svelte': { header: null, body: ['svelte', '__svelte'], meta: [] },

  // CMS
  'WordPress': { header: ['x-powered-by:wordpress'], body: ['wp-content', 'wp-includes', 'wp-json'], meta: ['wordpress', 'generator.*wordpress'] },
  'Drupal': { header: ['x-drupal'], body: ['drupal.js', 'sites/default', 'drupal-settings'], meta: ['drupal'] },
  'Joomla': { header: null, body: ['/media/jui/', 'joomla'], meta: ['joomla'] },

  // Servers
  'Nginx': { header: ['server:nginx'], body: [], meta: [] },
  'Apache': { header: ['server:apache'], body: [], meta: [] },
  'Cloudflare': { header: ['server:cloudflare', 'cf-ray'], body: [], meta: [] },
  'IIS': { header: ['server:microsoft-iis'], body: [], meta: [] },

  // Languages
  'PHP': { header: ['x-powered-by:php'], body: ['.php'], meta: [] },
  'ASP.NET': { header: ['x-powered-by:asp.net', 'x-aspnet-version'], body: ['.aspx', '.ashx'], meta: [] },
  'Express.js': { header: ['x-powered-by:express'], body: [], meta: [] },

  // CDN/Infrastructure
  'AWS': { header: ['x-amz', 'x-amzn'], body: ['amazonaws.com', 'cloudfront.net'], meta: [] },
  'Google Cloud': { header: ['x-goog'], body: ['googleapis.com', 'gstatic.com'], meta: [] },
  'Vercel': { header: ['x-vercel', 'server:vercel'], body: [], meta: [] },

  // Analytics
  'Google Analytics': { header: null, body: ['google-analytics.com', 'gtag', 'ga.js', 'analytics.js', 'googletagmanager'], meta: [] },
  'Facebook Pixel': { header: null, body: ['facebook.com/tr', 'fbevents.js', 'fbq('], meta: [] },
};

async function runTechDetection(url) {
  const response = await axios.get(url, {
    timeout: 10000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      'User-Agent': 'SecurityTestingTool/1.0',
    },
  });

  const headers = response.headers;
  const body = (response.data || '').toString().toLowerCase();
  const headerStr = Object.entries(headers)
    .map(([k, v]) => `${k}:${v}`)
    .join('\n')
    .toLowerCase();

  const detected = [];

  for (const [tech, patterns] of Object.entries(TECH_PATTERNS)) {
    let found = false;
    const evidence = [];

    // Check headers
    if (patterns.header) {
      for (const hp of patterns.header) {
        if (headerStr.includes(hp)) {
          found = true;
          evidence.push(`Header: ${hp}`);
        }
      }
    }

    // Check body content
    if (patterns.body) {
      for (const bp of patterns.body) {
        if (body.includes(bp.toLowerCase())) {
          found = true;
          evidence.push(`Body: ${bp}`);
        }
      }
    }

    // Check meta tags
    if (patterns.meta) {
      for (const mp of patterns.meta) {
        const regex = new RegExp(mp, 'i');
        if (regex.test(body)) {
          found = true;
          evidence.push(`Meta: ${mp}`);
        }
      }
    }

    if (found) {
      detected.push({ technology: tech, evidence });
    }
  }

  // Security concerns from detected technologies
  const concerns = [];
  if (detected.some((d) => ['PHP', 'ASP.NET'].includes(d.technology))) {
    const serverTech = detected.find((d) => ['PHP', 'ASP.NET'].includes(d.technology));
    if (headers['x-powered-by']) {
      concerns.push({
        severity: 'medium',
        message: `גרסת ${serverTech.technology} נחשפת דרך header - מומלץ להסתיר`,
      });
    }
  }

  if (headers['server'] && /\d/.test(headers['server'])) {
    concerns.push({
      severity: 'medium',
      message: 'גרסת השרת נחשפת - מומלץ להסתיר מידע על גרסה',
    });
  }

  return {
    detected,
    totalDetected: detected.length,
    concerns,
    categories: {
      frameworks: detected.filter((d) =>
        ['React', 'Vue.js', 'Angular', 'jQuery', 'Svelte'].includes(d.technology)
      ),
      cms: detected.filter((d) =>
        ['WordPress', 'Drupal', 'Joomla'].includes(d.technology)
      ),
      servers: detected.filter((d) =>
        ['Nginx', 'Apache', 'Cloudflare', 'IIS'].includes(d.technology)
      ),
      infrastructure: detected.filter((d) =>
        ['AWS', 'Google Cloud', 'Vercel'].includes(d.technology)
      ),
    },
  };
}

module.exports = { runTechDetection };
