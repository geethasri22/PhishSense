import { ClassificationLevel, SeverityLevel, EmailAnalysisRequest } from '../types/index.js';

export interface ScoredResult {
  classification: ClassificationLevel;
  riskScore: number;
  confidence: number;
  severity: SeverityLevel;
  reasons: string[];
  recommendation: string;
}

const TOP_TARGET_DOMAINS = [
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

const HIGH_RISK_ATTACHMENT_EXTS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.cpl',
  '.iso', '.img', '.ps1', '.jar', '.htm', '.html', '.svg', '.zip.exe'
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.cc', '.ru', '.cn'];

const URGENCY_KEYWORDS = [
  'urgent action required',
  'account suspended',
  'account locked',
  'verify your account',
  'confirm your identity',
  'security alert',
  'unauthorized login',
  'password expired',
  'billing failure',
  'payment declined',
  'immediate action',
  'wire transfer',
  'gift card',
  'tax audit',
  'ssn verification',
  'click here immediately',
];

export class RiskScoringService {
  /**
   * Deterministic local analysis engine.
   */
  public evaluateRules(email: EmailAnalysisRequest): ScoredResult {
    let score = 0;
    const reasons: string[] = [];

    const sender = email.sender.trim().toLowerCase();
    const senderDomain = this.extractDomain(sender);
    const subject = (email.subject || '').toLowerCase();
    const body = (email.body || '').toLowerCase();

    // 0. Flagged Phishing & Spam Sender Check
    const KNOWN_PHISHING_SENDERS = [
      'geethasrilakshmi0306@gmail.com',
      'security-alert-update@suspicious-domain.xyz',
      'paypal-support@security-verify-net.info',
    ];

    if (KNOWN_PHISHING_SENDERS.some((s) => sender.includes(s))) {
      score += 75;
      reasons.push(`🚩 SENDER RED FLAG: "${sender}" is a flagged spam & phishing email sender address.`);
    }

    // 1. Sender Domain & Lookalike Analysis
    if (senderDomain) {
      const spoofedTarget = this.findSpoofedDomain(senderDomain);
      if (spoofedTarget) {
        score += 45;
        reasons.push(`Sender domain "${senderDomain}" resembles protected domain "${spoofedTarget}" (Lookalike Domain / Typosquatting).`);
      }

      const senderTld = '.' + senderDomain.split('.').pop();
      if (SUSPICIOUS_TLDS.includes(senderTld)) {
        score += 25;
        reasons.push(`Sender domain uses high-risk top-level domain (${senderTld}).`);
      }
    }

    // 2. Link Discrepancy & Suspicious URL Analysis
    if (email.links && email.links.length > 0) {
      let mismatchCount = 0;
      let ipLinkCount = 0;
      let suspiciousTldLinkCount = 0;

      for (const link of email.links) {
        const href = (link.href || '').trim();
        const text = (link.text || '').trim();

        // Check if text looks like a domain/URL but href goes somewhere else
        if (text.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.[a-z]{2,}/i)) {
          const textDomain = this.extractDomain(text);
          const hrefDomain = this.extractDomain(href);
          if (textDomain && hrefDomain && textDomain !== hrefDomain) {
            mismatchCount++;
          }
        }

        // IP address URL check
        if (href.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
          ipLinkCount++;
        }

        // High risk TLDs in links
        const hrefDomain = this.extractDomain(href);
        if (hrefDomain) {
          const tld = '.' + hrefDomain.split('.').pop();
          if (SUSPICIOUS_TLDS.includes(tld)) {
            suspiciousTldLinkCount++;
          }
        }
      }

      if (mismatchCount > 0) {
        score += 35;
        reasons.push(`Found ${mismatchCount} link(s) where displayed text domain does not match actual hyperlink target.`);
      }

      if (ipLinkCount > 0) {
        score += 30;
        reasons.push(`Found ${ipLinkCount} hyperlink(s) pointing directly to raw IP addresses instead of registered domain names.`);
      }

      if (suspiciousTldLinkCount > 0) {
        score += 20;
        reasons.push(`Found ${suspiciousTldLinkCount} hyperlink(s) leading to suspicious or high-risk domain extensions.`);
      }
    }

    // 3. Urgent / Fear / Social Engineering Content Analysis
    let keywordHits = 0;
    const combinedContent = `${subject} ${body}`;
    for (const keyword of URGENCY_KEYWORDS) {
      if (combinedContent.includes(keyword)) {
        keywordHits++;
      }
    }

    if (keywordHits >= 3) {
      score += 30;
      reasons.push(`High density of high-pressure social engineering and urgency phrases detected (${keywordHits} matches).`);
    } else if (keywordHits >= 1) {
      score += 15;
      reasons.push(`Email contains psychological urgency phrases commonly found in phishing lures.`);
    }

    // 4. Attachment Security Check
    if (email.attachments && email.attachments.length > 0) {
      let highRiskAttachCount = 0;
      let doubleExtCount = 0;

      for (const att of email.attachments) {
        const name = (att.filename || '').toLowerCase();
        if (HIGH_RISK_ATTACHMENT_EXTS.some((ext) => name.endsWith(ext))) {
          highRiskAttachCount++;
        }
        if (name.match(/\.(pdf|doc|docx|jpg|png)\.(exe|scr|vbs|bat|js|iso)$/)) {
          doubleExtCount++;
        }
      }

      if (doubleExtCount > 0) {
        score += 40;
        reasons.push(`Detected attachment with dangerous double file extension (e.g. .pdf.exe).`);
      }

      if (highRiskAttachCount > 0) {
        score += 30;
        reasons.push(`Email contains high-risk executable or script attachment types (${highRiskAttachCount} file(s)).`);
      }
    }

    // Cap score at 100
    const finalScore = Math.min(100, Math.max(0, score));

    if (reasons.length === 0) {
      reasons.push('No suspicious indicators or security anomalies detected by PhishSense deterministic engine.');
    }

    const classification = this.getClassification(finalScore);
    const severity = this.getSeverity(finalScore);
    const recommendation = this.getRecommendation(classification);

    return {
      classification,
      riskScore: finalScore,
      confidence: 0.92,
      severity,
      reasons,
      recommendation,
    };
  }

  /**
   * Blends rule-based score (80%) with AI score (20%) while ensuring severe rule violations cannot be overridden by AI.
   */
  public combineScores(ruleResult: ScoredResult, aiResult?: { score: number; reasons: string[] }): ScoredResult {
    if (!aiResult) {
      return ruleResult;
    }

    // Weighted blend: 80% rule, 20% AI
    let blendedScore = Math.round(ruleResult.riskScore * 0.8 + aiResult.score * 0.2);

    // Safeguard: If deterministic engine scored high risk (>= 60), AI cannot downgrade score below 50.
    if (ruleResult.riskScore >= 60) {
      blendedScore = Math.max(50, blendedScore);
    }

    const mergedReasons = Array.from(new Set([...ruleResult.reasons, ...(aiResult.reasons || [])]));
    const classification = this.getClassification(blendedScore);
    const severity = this.getSeverity(blendedScore);
    const recommendation = this.getRecommendation(classification);

    return {
      classification,
      riskScore: blendedScore,
      confidence: 0.96,
      severity,
      reasons: mergedReasons,
      recommendation,
    };
  }

  private extractDomain(emailOrUrl: string): string | null {
    if (!emailOrUrl) return null;
    const emailMatch = emailOrUrl.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) return emailMatch[1].toLowerCase();

    const urlMatch = emailOrUrl.match(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (urlMatch) return urlMatch[1].toLowerCase();

    if (emailOrUrl.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
      return emailOrUrl.toLowerCase();
    }
    return null;
  }

  private findSpoofedDomain(domain: string): string | null {
    for (const target of TOP_TARGET_DOMAINS) {
      if (domain === target) continue;
      const dist = this.levenshteinDistance(domain, target);
      if (dist >= 1 && dist <= 2) {
        return target;
      }
      // Check character substitution e.g., micros0ft -> microsoft
      const normalizedDomain = domain.replace(/0/g, 'o').replace(/1/g, 'l').replace(/vv/g, 'w');
      if (normalizedDomain === target) {
        return target;
      }
    }
    return null;
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
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

  private getClassification(score: number): ClassificationLevel {
    if (score >= 80) return 'PHISHING';
    if (score >= 60) return 'HIGH_RISK';
    if (score >= 40) return 'SUSPICIOUS';
    if (score >= 20) return 'SPAM';
    return 'SAFE';
  }

  private getSeverity(score: number): SeverityLevel {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 35) return 'MEDIUM';
    return 'LOW';
  }

  private getRecommendation(classification: ClassificationLevel): string {
    switch (classification) {
      case 'PHISHING':
        return 'DO NOT click links, download attachments, or reply. Report this email immediately.';
      case 'HIGH_RISK':
        return 'Exercise extreme caution. Sender domain and links exhibit high threat indicators.';
      case 'SUSPICIOUS':
        return 'Verify the sender via an independent communication channel before interacting with links.';
      case 'SPAM':
        return 'This email exhibits unsolicited bulk mail characteristics. Proceed with caution.';
      case 'SAFE':
      default:
        return 'Email appears safe to read. Standard email vigilance is always advised.';
    }
  }
}
