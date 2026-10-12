const JOB_FEE_SCAM_KEYWORDS = [
  'pay a registration fee',
  'registration fee of',
  'pay a fee of',
  'submit your aadhaar',
  'aadhaar and bank details',
  'selected for a software developer position',
  'selected for a position',
  'confirm your job',
  'salary of ₹',
  'salary of rs',
  'lpa',
  'processing fee required',
  'advance fee',
  'recruitment team',
];

const ACCOUNT_LOCK_KEYWORDS = [
  'unauthorized login attempt',
  'suspicious login attempt',
  'unrecognized device',
  'temporarily locked your account',
  'restore your account',
  'verify your identity',
  'failure to verify your details',
  'permanent suspension of your services',
  'permanent suspension',
  'immediate action required',
  'account access locked',
  'security team',
  'account security department',
];

const PACKAGE_SCAM_KEYWORDS = [
  'package delivery is on hold',
  'delivery is on hold',
  'shipment on hold',
  'update your delivery address',
  'customs fee required',
  'package pending delivery',
  'failed delivery attempt',
];

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
  'urgent',
];

const HIGH_RISK_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.iso', '.ps1', '.pdf.exe'];

export interface ContentCheckResult {
  score: number;
  reasons: string[];
}

export function analyzeContentAndAttachments(
  subject: string,
  body: string,
  attachments: Array<{ filename: string; mimeType?: string; size?: number }>
): ContentCheckResult {
  const reasons: string[] = [];
  let score = 0;

  const combined = `${subject || ''} ${body || ''}`.toLowerCase();

  // 1. Job Fee & Financial Advance Fee Scam Check
  const jobHit = JOB_FEE_SCAM_KEYWORDS.find((k) => combined.includes(k));
  if (jobHit) {
    score += 55;
    reasons.push(`🚩 JOB & FINANCIAL SCAM: Email demands registration fee / upfront payment or sensitive bank/Aadhaar data.`);
  }

  // 2. Account Security & Login Attempt Lock Lures
  const accountHit = ACCOUNT_LOCK_KEYWORDS.find((k) => combined.includes(k));
  if (accountHit) {
    score += 50;
    reasons.push(`🚩 ACCOUNT TAKEOVER LURE: Email uses account lock threats / unauthorized login attempt lures.`);
  }

  // 3. Package Delivery Hold Scam
  const packageHit = PACKAGE_SCAM_KEYWORDS.find((k) => combined.includes(k));
  if (packageHit) {
    score += 50;
    reasons.push(`🚩 POSTAL SCAM: Email uses fake package delivery hold notifications to lure clicks.`);
  }

  // 4. Psychological Urgency Density Check
  let hits = 0;
  for (const keyword of URGENCY_KEYWORDS) {
    if (combined.includes(keyword)) {
      hits++;
    }
  }

  if (hits >= 3) {
    score += 35;
    reasons.push(`High density of social engineering and high-pressure urgency phrases (${hits} detected).`);
  } else if (hits >= 1 && !accountHit && !jobHit && !packageHit) {
    score += 25;
    reasons.push('Email subject or body contains psychological pressure & urgency keywords.');
  }

  // 5. Attachments Analysis
  if (attachments && attachments.length > 0) {
    let highRiskCount = 0;
    let doubleExtCount = 0;

    for (const att of attachments) {
      const name = (att.filename || '').toLowerCase();
      if (HIGH_RISK_EXTS.some((ext) => name.endsWith(ext))) {
        highRiskCount++;
      }
      if (name.match(/\.(pdf|doc|docx|jpg|png)\.(exe|scr|vbs|bat|js|iso)$/)) {
        doubleExtCount++;
      }
    }

    if (doubleExtCount > 0) {
      score += 40;
      reasons.push('Detected attachment with suspicious double file extension.');
    }

    if (highRiskCount > 0) {
      score += 30;
      reasons.push(`Email contains ${highRiskCount} executable or script attachment file(s).`);
    }
  }

  return { score, reasons };
}
