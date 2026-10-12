export interface UrlCheckResult {
  score: number;
  reasons: string[];
  mismatchedLinks: Array<{ text: string; href: string }>;
}

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.cc', '.ru', '.cn'];

export function analyzeLinks(links: Array<{ text: string; href: string }>): UrlCheckResult {
  const reasons: string[] = [];
  const mismatchedLinks: Array<{ text: string; href: string }> = [];
  let score = 0;

  if (!links || links.length === 0) {
    return { score: 0, reasons: [], mismatchedLinks: [] };
  }

  let mismatchCount = 0;
  let ipLinkCount = 0;
  let suspiciousTldCount = 0;

  for (const link of links) {
    const text = (link.text || '').trim();
    const href = (link.href || '').trim();

    // Text domain vs href domain discrepancy
    if (text.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.[a-z]{2,}/i)) {
      const textDomain = extractDomain(text);
      const hrefDomain = extractDomain(href);
      if (textDomain && hrefDomain && textDomain !== hrefDomain) {
        mismatchCount++;
        mismatchedLinks.push({ text, href });
      }
    }

    // Direct IP address link check
    if (href.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
      ipLinkCount++;
    }

    // High risk TLD check
    const hrefDomain = extractDomain(href);
    if (hrefDomain) {
      const tld = '.' + hrefDomain.split('.').pop();
      if (SUSPICIOUS_TLDS.includes(tld)) {
        suspiciousTldCount++;
      }
    }
  }

  if (mismatchCount > 0) {
    score += 35;
    reasons.push(`Detected ${mismatchCount} link(s) where displayed text domain does not match actual link destination.`);
  }

  if (ipLinkCount > 0) {
    score += 30;
    reasons.push(`Detected ${ipLinkCount} link(s) pointing directly to raw IP addresses.`);
  }

  if (suspiciousTldCount > 0) {
    score += 20;
    reasons.push(`Detected ${suspiciousTldCount} link(s) targeting suspicious top-level domains.`);
  }

  return { score, reasons, mismatchedLinks };
}

function extractDomain(str: string): string | null {
  const match = str.match(/(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
  return match ? match[1].toLowerCase() : null;
}
