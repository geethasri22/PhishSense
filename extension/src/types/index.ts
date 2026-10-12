export type ClassificationLevel = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'HIGH_RISK' | 'PHISHING';
export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface EmailData {
  id?: string;
  sender: string;
  senderName?: string;
  subject: string;
  body: string;
  links: Array<{
    text: string;
    href: string;
  }>;
  attachments: Array<{
    filename: string;
    mimeType?: string;
    size?: number;
  }>;
}

export interface SecurityAnalysisResult {
  messageHash: string;
  classification: ClassificationLevel;
  riskScore: number;
  confidence: number;
  severity: SeverityLevel;
  reasons: string[];
  recommendation: string;
  timestamp: string;
  isAiAnalyzed: boolean;
  userDecision?: 'NONE' | 'MARKED_SAFE' | 'REPORTED' | 'IGNORED';
  /** The flagged sender address of the email being analysed */
  sender?: string;
  /** The Gmail inbox account currently viewing the email */
  inboxAccount?: string;
}

export interface UserSettings {
  autoScanning: boolean;
  aiAnalysisEnabled: boolean;
  urlAnalysisEnabled: boolean;
  attachmentAnalysisEnabled: boolean;
  showWarnings: boolean;
  showExplanations: boolean;
  reportConfirmation: boolean;
  privacyMode: boolean;
  trustedSenders: string[];
  blockedSenders: string[];
}

export interface SecurityStats {
  totalScanned: number;
  safeCount: number;
  spamCount: number;
  suspiciousCount: number;
  highRiskCount: number;
  phishingCount: number;
  reportsCount: number;
  markedSafeCount: number;
}
