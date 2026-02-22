const net = require('net');

const COMMON_PORTS = [
  { port: 21, service: 'FTP', risk: 'high', description: 'שירות העברת קבצים - לרוב לא מאובטח' },
  { port: 22, service: 'SSH', risk: 'low', description: 'גישה מרחוק מאובטחת' },
  { port: 23, service: 'Telnet', risk: 'high', description: 'גישה מרחוק לא מוצפנת - מסוכן!' },
  { port: 25, service: 'SMTP', risk: 'medium', description: 'שירות דואר אלקטרוני' },
  { port: 53, service: 'DNS', risk: 'low', description: 'שירות DNS' },
  { port: 80, service: 'HTTP', risk: 'low', description: 'שרת ווב רגיל' },
  { port: 110, service: 'POP3', risk: 'medium', description: 'שירות דואר - מומלץ להשתמש ב-POP3S' },
  { port: 143, service: 'IMAP', risk: 'medium', description: 'שירות דואר - מומלץ להשתמש ב-IMAPS' },
  { port: 443, service: 'HTTPS', risk: 'low', description: 'שרת ווב מאובטח' },
  { port: 445, service: 'SMB', risk: 'high', description: 'שיתוף קבצים - לא צריך להיות חשוף לאינטרנט' },
  { port: 993, service: 'IMAPS', risk: 'low', description: 'שירות דואר מאובטח' },
  { port: 995, service: 'POP3S', risk: 'low', description: 'שירות דואר מאובטח' },
  { port: 3306, service: 'MySQL', risk: 'high', description: 'בסיס נתונים - לא צריך להיות חשוף!' },
  { port: 3389, service: 'RDP', risk: 'high', description: 'שולחן עבודה מרוחק - סיכון אבטחה' },
  { port: 5432, service: 'PostgreSQL', risk: 'high', description: 'בסיס נתונים - לא צריך להיות חשוף!' },
  { port: 5900, service: 'VNC', risk: 'high', description: 'שולחן עבודה מרוחק - לא מאובטח' },
  { port: 6379, service: 'Redis', risk: 'high', description: 'בסיס נתונים - לא צריך להיות חשוף!' },
  { port: 8080, service: 'HTTP Alt', risk: 'medium', description: 'שרת ווב חלופי' },
  { port: 8443, service: 'HTTPS Alt', risk: 'low', description: 'שרת ווב מאובטח חלופי' },
  { port: 27017, service: 'MongoDB', risk: 'high', description: 'בסיס נתונים - לא צריך להיות חשוף!' },
];

function checkPort(hostname, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      status = 'open';
      socket.destroy();
    });

    socket.on('timeout', () => {
      status = 'filtered';
      socket.destroy();
    });

    socket.on('error', () => {
      status = 'closed';
    });

    socket.on('close', () => {
      resolve(status);
    });

    socket.connect(port, hostname);
  });
}

async function runPortCheck(hostname) {
  // Run port checks in batches to avoid overwhelming the target
  const batchSize = 5;
  const results = [];

  for (let i = 0; i < COMMON_PORTS.length; i += batchSize) {
    const batch = COMMON_PORTS.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (portInfo) => {
        const status = await checkPort(hostname, portInfo.port);
        return {
          ...portInfo,
          status,
        };
      })
    );
    results.push(...batchResults);
  }

  const openPorts = results.filter((r) => r.status === 'open');
  const highRiskOpen = openPorts.filter((r) => r.risk === 'high');

  let score = 100;
  // Deduct points for risky open ports
  for (const port of openPorts) {
    if (port.risk === 'high') score -= 15;
    else if (port.risk === 'medium') score -= 5;
  }
  score = Math.max(0, score);

  return {
    score,
    totalScanned: results.length,
    openPorts: openPorts.length,
    results,
    highRiskPorts: highRiskOpen,
    warnings: highRiskOpen.map((p) => ({
      severity: 'high',
      message: `פורט ${p.port} (${p.service}) פתוח - ${p.description}`,
    })),
  };
}

module.exports = { runPortCheck };
