const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolveCname = promisify(dns.resolveCname);

async function safeResolve(fn, hostname) {
  try {
    return await fn(hostname);
  } catch {
    return [];
  }
}

async function runDnsCheck(hostname) {
  const [ipv4, ipv6, mx, ns, txt, cname] = await Promise.all([
    safeResolve(resolve4, hostname),
    safeResolve(resolve6, hostname),
    safeResolve(resolveMx, hostname),
    safeResolve(resolveNs, hostname),
    safeResolve(resolveTxt, hostname),
    safeResolve(resolveCname, hostname),
  ]);

  // Check for security-related DNS records
  const securityRecords = [];
  const flatTxt = txt.map((t) => t.join(' '));

  // SPF record check
  const spfRecord = flatTxt.find((t) => t.startsWith('v=spf1'));
  securityRecords.push({
    type: 'SPF',
    present: !!spfRecord,
    value: spfRecord || null,
    description: 'מגן מפני זיוף אימייל (email spoofing)',
  });

  // DMARC check
  let dmarcRecords = [];
  try {
    dmarcRecords = await resolve4(`_dmarc.${hostname}`).catch(() => []);
    const dmarcTxt = await safeResolve(promisify(dns.resolveTxt), `_dmarc.${hostname}`);
    const dmarcFlat = dmarcTxt.map((t) => t.join(' '));
    const dmarcRecord = dmarcFlat.find((t) => t.startsWith('v=DMARC1'));
    securityRecords.push({
      type: 'DMARC',
      present: !!dmarcRecord,
      value: dmarcRecord || null,
      description: 'מדיניות אימות אימייל מבוססת דומיין',
    });
  } catch {
    securityRecords.push({
      type: 'DMARC',
      present: false,
      value: null,
      description: 'מדיניות אימות אימייל מבוססת דומיין',
    });
  }

  // CAA record check
  let caaRecords = [];
  try {
    const resolveCaa = promisify(dns.resolveCaa);
    caaRecords = await resolveCaa(hostname).catch(() => []);
  } catch {
    // CAA not supported on all systems
  }
  securityRecords.push({
    type: 'CAA',
    present: caaRecords.length > 0,
    value: caaRecords.length > 0 ? caaRecords : null,
    description: 'מגביל אילו CAs יכולים להנפיק אישורים לדומיין',
  });

  const score = calculateDnsScore(ipv4, ipv6, securityRecords);

  return {
    score,
    hostname,
    ipv4,
    ipv6,
    mx: mx.sort((a, b) => a.priority - b.priority),
    ns,
    cname,
    txtRecordCount: txt.length,
    securityRecords,
  };
}

function calculateDnsScore(ipv4, ipv6, securityRecords) {
  let score = 0;

  if (ipv4.length > 0) score += 20;
  if (ipv6.length > 0) score += 20;

  for (const rec of securityRecords) {
    if (rec.present) score += 20;
  }

  return Math.min(score, 100);
}

module.exports = { runDnsCheck };
