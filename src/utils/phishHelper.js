const { URL } = require("url");

const SUSPICIOUS_TOKENS = ['login','secure','account','update','verify','bank','confirm','webscr','signin','paypal','amazon'];

function safeNormalizeUrl(input) {
  if (!input || typeof input !== 'string') throw new Error('invalid_url');
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = 'http://' + s;
  try {
    return new URL(s);
  } catch (e) {
    throw new Error('invalid_url');
  }
}

function extractFeatures(urlStr) {
  try {
    const url = safeNormalizeUrl(urlStr);
    const host = url.hostname.toLowerCase();
    const path = (url.pathname || '') + (url.search || '');

    const suspicious_tokens = SUSPICIOUS_TOKENS.filter(t => urlStr.toLowerCase().includes(t));

    const features = {
      url_length: urlStr.length,
      host_length: host.length,
      count_dots: (host.match(/\./g) || []).length,
      has_at: urlStr.includes('@') ? 1 : 0,
      has_https: url.protocol === 'https:' ? 1 : 0,
      is_ip: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 1 : 0,
      contains_punycode: host.includes('xn--') ? 1 : 0,
      num_subdirs: (path.match(/\//g) || []).length,
      suspicious_tokens_count: suspicious_tokens.length,
      long_url: urlStr.length > 200 ? 1 : 0
    };
    return { features, suspicious_tokens, host };
  } catch (e) {
    return { error: 'invalid_url' };
  }
}

function heuristicScore(features) {
  // weighted scoring (0-100)
  let score = 0;
  score += features.is_ip ? 30 : 0;
  score += features.has_at ? 25 : 0;
  score += features.contains_punycode ? 20 : 0;
  score += features.suspicious_tokens_count * 10;
  score += features.long_url ? 10 : 0;
  score += (features.count_dots > 3) ? 5 : 0;
  score += features.num_subdirs > 4 ? 5 : 0;
  // reduce risk for HTTPS
  score -= features.has_https ? 10 : 0;

  // clamp
  score = Math.max(0, Math.min(100, score));
  return score;
}

function mapScoreToLabel(score) {
  if (score >= 75) return 'phishing';
  if (score >= 40) return 'suspicious';
  return 'safe';
}

module.exports = {
  extractFeatures,
  heuristicScore,
  mapScoreToLabel
};
