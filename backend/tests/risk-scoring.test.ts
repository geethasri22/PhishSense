import { RiskScoringService } from '../src/services/risk-scoring.service';

describe('RiskScoringService', () => {
  let scoringService: RiskScoringService;

  beforeEach(() => {
    scoringService = new RiskScoringService();
  });

  it('should classify clean legitimate email as SAFE', () => {
    const email = {
      sender: 'notifications@google.com',
      subject: 'Weekly Developer Update',
      body: 'Here is your weekly summary of activity.',
      links: [{ text: 'View Report', href: 'https://google.com/dashboard' }],
      attachments: [],
    };

    const result = scoringService.evaluateRules(email);
    expect(result.classification).toBe('SAFE');
    expect(result.riskScore).toBeLessThan(20);
  });

  it('should detect lookalike typosquatting sender domain', () => {
    const email = {
      sender: 'security@micros0ft.com',
      subject: 'Account Notice',
      body: 'Please review your account.',
      links: [],
      attachments: [],
    };

    const result = scoringService.evaluateRules(email);
    expect(result.riskScore).toBeGreaterThanOrEqual(45);
    expect(result.reasons.some((r) => r.includes('Lookalike Domain'))).toBe(true);
  });

  it('should detect link mismatch anchor text vs href destination', () => {
    const email = {
      sender: 'service@paypal.com',
      subject: 'Verification Required',
      body: 'Click below to verify.',
      links: [{ text: 'https://paypal.com/login', href: 'http://phishing-site-scam.ru/login' }],
      attachments: [],
    };

    const result = scoringService.evaluateRules(email);
    expect(result.riskScore).toBeGreaterThanOrEqual(35);
    expect(result.reasons.some((r) => r.includes('does not match actual hyperlink target'))).toBe(true);
  });

  it('should flag double extension executable attachment', () => {
    const email = {
      sender: 'hr@company.com',
      subject: 'Invoice Attachment',
      body: 'See attached invoice.',
      links: [],
      attachments: [{ filename: 'Invoice_2026.pdf.exe' }],
    };

    const result = scoringService.evaluateRules(email);
    expect(result.riskScore).toBeGreaterThanOrEqual(40);
    expect(result.reasons.some((r) => r.includes('double file extension'))).toBe(true);
  });
});
