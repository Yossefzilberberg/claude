const tls = require('tls');

async function runSslCheck(hostname) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('SSL connection timed out'));
    }, 10000);

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false, // We want to inspect even invalid certs
      },
      () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();

        socket.end();

        if (!cert || !cert.subject) {
          resolve({
            valid: false,
            error: 'No certificate found',
            score: 0,
          });
          return;
        }

        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo;
        const isNotYetValid = now < validFrom;

        // Score calculation
        let score = 0;
        const issues = [];

        if (authorized) score += 30;
        else issues.push({ severity: 'high', message: 'האישור אינו מאומת (untrusted CA)' });

        if (!isExpired && !isNotYetValid) score += 20;
        else if (isExpired) issues.push({ severity: 'high', message: 'האישור פג תוקף!' });
        else issues.push({ severity: 'high', message: 'האישור עדיין לא תקף' });

        if (daysUntilExpiry > 30) score += 10;
        else if (daysUntilExpiry > 0) issues.push({ severity: 'medium', message: `האישור יפוג בעוד ${daysUntilExpiry} ימים` });

        // Protocol check
        const goodProtocols = ['TLSv1.2', 'TLSv1.3'];
        if (goodProtocols.includes(protocol)) score += 20;
        else issues.push({ severity: 'high', message: `פרוטוקול לא מאובטח: ${protocol}` });

        if (protocol === 'TLSv1.3') score += 10;

        // Cipher strength
        if (cipher && cipher.name && !cipher.name.includes('RC4') && !cipher.name.includes('DES')) {
          score += 10;
        } else {
          issues.push({ severity: 'medium', message: 'צופן חלש בשימוש' });
        }

        resolve({
          valid: authorized,
          score: Math.min(score, 100),
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysUntilExpiry,
          isExpired,
          protocol,
          cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint256 || cert.fingerprint,
          subjectAltNames: cert.subjectaltname || '',
          issues,
        });
      }
    );

    socket.on('error', (err) => {
      clearTimeout(timeout);
      reject(new Error('SSL connection failed: ' + err.message));
    });
  });
}

module.exports = { runSslCheck };
