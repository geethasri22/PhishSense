const PROTECTED_DOMAINS = [
  'paypal.com',
  'microsoft.com',
  'google.com',
  'apple.com',
  'amazon.com',
  'chase.com',
  'wellsfargo.com',
  'bankofamerica.com',
  'netflix.com',
  'linkedin.com',
  'facebook.com',
  'instagram.com',
  'dropbox.com',
  'docusign.com',
  'stripe.com',
];

const FREE_WEBMAIL_DOMAINS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'aol.com', 'mail.com', 'protonmail.com'];

const ORGANIZATIONAL_ROLE_KEYWORDS = [
  'security team',
  'recruitment team',
  'account security',
  'support team',
  'hr team',
  'verification team',
  'official notification',
  'help desk',
  'admin team',
  'customer support',
  'package delivery',
  'delivery service',
  'bank alert',
  'payroll',
  'hiring manager',
  'recruitment',
  'security department',
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.cc', '.ru', '.cn'];

const KNOWN_PHISHING_SENDERS = [
  'geethasrilakshmi0306@gmail.com',
  'security-alert-update@suspicious-domain.xyz',
  'paypal-support@security-verify-net.info',
];

export interface DomainCheckResult {
  score: number;
  reasons: string[];
  senderDomain: string | null;
}

export function analyzeSenderDomain(sender: string, senderName: string = ''): DomainCheckResult {
  const reasons: string[] = [];
  let score = 0;

  const cleanSender = sender.trim().toLowerCase();
  const cleanName = (senderName || '').trim().toLowerCase();

  // 1. Check known/configured phishing senders
  if (KNOWN_PHISHING_SENDERS.some((s) => cleanSender.includes(s))) {
    score += 75;
    reasons.push(`🚩 SENDER RED FLAG: "${cleanSender}" is a flagged spam & phishing email sender.`);
  }

  const domain = extractDomainFromSender(sender);
  if (!domain) {
    return { score: Math.max(score, 10), reasons: [...reasons, 'Sender email format is missing a valid domain name.'], senderDomain: null };
  }

  // 2. Free Webmail Impersonation Check (@gmail.com claiming to be Security Team / Recruitment / Support)
  if (FREE_WEBMAIL_DOMAINS.includes(domain)) {
    const combined = `${cleanSender} ${cleanName}`;
    const roleHit = ORGANIZATIONAL_ROLE_KEYWORDS.find((role) => combined.includes(role));
    if (roleHit) {
      score += 50;
      reasons.push(`🚩 SENDER IMPERSONATION: Personal webmail (${domain}) claiming to be official "${roleHit.toUpperCase()}".`);
    }
  }

  // 3. Multi-hyphen Corporate Brand Spoofing Check (e.g. netflix-support-portal.com)
  for (const target of PROTECTED_DOMAINS) {
    const brandName = target.split('.')[0];
    if (domain !== target && domain.includes(brandName)) {
      if (domain.includes('-') || domain.includes('support') || domain.includes('portal') || domain.includes('security') || domain.includes('verify')) {
        score += 55;
        reasons.push(`🚩 BRAND SPOOFING DOMAIN: Sender domain "${domain}" impersonates "${target}".`);
        break;
      }
    }
  }

  // 4. Lookalike domain check (Levenshtein & Homoglyphs)
  for (const target of PROTECTED_DOMAINS) {
    if (domain === target) continue;
    const dist = levenshtein(domain, target);
    if (dist >= 1 && dist <= 2) {
      score += 45;
      reasons.push(`Sender domain "${domain}" is a suspicious lookalike for "${target}".`);
      break;
    }
    const normalized = domain.replace(/0/g, 'o').replace(/1/g, 'l').replace(/vv/g, 'w');
    if (normalized === target) {
      score += 45;
      reasons.push(`Sender domain "${domain}" uses visual homoglyphs to impersonate "${target}".`);
      break;
    }
  }

  // 5. Suspicious TLD check
  const tld = '.' + domain.split('.').pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 25;
    reasons.push(`Sender address originates from high-risk domain extension (${tld}).`);
  }

  return { score, reasons, senderDomain: domain };
}

function extractDomainFromSender(sender: string): string | null {
  const match = sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase() : null;
}

function levenshtein(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
        );
      }
    }
  }
  return matrix[b.length][a.length];
}
