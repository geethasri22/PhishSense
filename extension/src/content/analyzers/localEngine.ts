import { EmailData, SecurityAnalysisResult, ClassificationLevel, SeverityLevel } from '../../types/index.js';
import { analyzeSenderDomain } from './domainAnalyzer.js';
import { analyzeLinks } from './urlAnalyzer.js';
import { analyzeContentAndAttachments } from './contentAnalyzer.js';

export function runLocalSecurityAnalysis(email: EmailData, hash: string, inboxAccount?: string): SecurityAnalysisResult {
  const domainRes = analyzeSenderDomain(email.sender, email.senderName || '');
  const linkRes = analyzeLinks(email.links || []);
  const contentRes = analyzeContentAndAttachments(email.subject, email.body, email.attachments || []);

  const totalScore = Math.min(100, Math.max(0, domainRes.score + linkRes.score + contentRes.score));
  const reasons = [...domainRes.reasons, ...linkRes.reasons, ...contentRes.reasons];

  if (reasons.length === 0) {
    reasons.push('No suspicious indicators or security anomalies detected by PhishSense engine.');
  }

  const classification = getClassification(totalScore);
  const severity = getSeverity(totalScore);
  const recommendation = getRecommendation(classification);

  return {
    messageHash: hash,
    classification,
    riskScore: totalScore,
    confidence: 0.92,
    severity,
    reasons,
    recommendation,
    timestamp: new Date().toISOString(),
    isAiAnalyzed: false,
    userDecision: 'NONE',
    sender: email.sender,
    inboxAccount: inboxAccount || 'unknown@gmail.com',
  };
}

function getClassification(score: number): ClassificationLevel {
  if (score >= 80) return 'PHISHING';
  if (score >= 60) return 'HIGH_RISK';
  if (score >= 40) return 'SUSPICIOUS';
  if (score >= 20) return 'SPAM';
  return 'SAFE';
}

function getSeverity(score: number): SeverityLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

function getRecommendation(classification: ClassificationLevel): string {
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
