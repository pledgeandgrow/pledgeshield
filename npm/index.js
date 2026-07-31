const { runScan, scanSync } = require('./index.js');

/**
 * Run a PledgeShield security scan asynchronously.
 * @param {Object} options - Scan options
 * @param {boolean} options.cve - Enable CVE checks
 * @param {string} options.format - Output format: text, json, html, sarif, markdown
 * @param {string} options.minSeverity - Minimum severity: critical, high, medium, low, info
 * @param {boolean} options.offline - Use cached CVE data only
 * @returns {Promise<string>} Scan report as string
 */
async function scan(options = {}) {
  return runScan(options);
}

module.exports = { scan, runScan, scanSync };
