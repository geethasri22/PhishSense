export type ClassificationLevel = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'HIGH_RISK' | 'PHISHING';
export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface EmailAnalysisRequest {
  sender: string;
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
  messageHash?: string;
}

export interface EmailAnalysisResponse {
  id?: string;
  messageHash: string;
  classification: ClassificationLevel;
  riskScore: number;
  confidence: number;
  severity: SeverityLevel;
  reasons: string[];
  recommendation: string;
  timestamp: string;
  isAiAnalyzed: boolean;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}
