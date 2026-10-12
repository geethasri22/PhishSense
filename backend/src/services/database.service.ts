import { pool } from '../database/db.js';
import { EmailAnalysisResponse, ClassificationLevel } from '../types/index.js';

export interface AnalysisRecord extends EmailAnalysisResponse {
  userAction?: 'NONE' | 'MARKED_SAFE' | 'REPORTED' | 'IGNORED';
  scannedAt: string;
}

export interface StatisticsData {
  totalScanned: number;
  safeCount: number;
  spamCount: number;
  suspiciousCount: number;
  highRiskCount: number;
  phishingCount: number;
  reportsCount: number;
  markedSafeCount: number;
}

export class DatabaseService {
  private inMemoryHistory: AnalysisRecord[] = [];
  private inMemoryTrusted: string[] = ['google.com', 'microsoft.com', 'github.com'];
  private inMemoryBlocked: string[] = ['phishing-domain-example.tk', 'scam-malware-test.ru'];
  private inMemoryStats: StatisticsData = {
    totalScanned: 0,
    safeCount: 0,
    spamCount: 0,
    suspiciousCount: 0,
    highRiskCount: 0,
    phishingCount: 0,
    reportsCount: 0,
    markedSafeCount: 0,
  };

  /**
   * Saves email analysis record to database or memory fallback.
   */
  public async saveAnalysis(analysis: EmailAnalysisResponse, senderDomain?: string): Promise<string> {
    const record: AnalysisRecord = {
      ...analysis,
      userAction: 'NONE',
      scannedAt: new Date().toISOString(),
    };

    try {
      const res = await pool.query(
        `INSERT INTO email_analysis
        (message_hash, sender_domain, classification, risk_score, confidence, severity, reasons, recommendation)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id`,
        [
          analysis.messageHash,
          senderDomain || null,
          analysis.classification,
          analysis.riskScore,
          analysis.confidence,
          analysis.severity,
          JSON.stringify(analysis.reasons),
          analysis.recommendation,
        ]
      );

      // Increment stats table
      await this.incrementStats(analysis.classification);

      return res.rows[0].id;
    } catch {
      // Fallback to memory
      record.id = 'mem-' + Math.random().toString(36).substring(2, 9);
      this.inMemoryHistory.unshift(record);
      this.updateInMemoryStats(analysis.classification);
      return record.id;
    }
  }

  public async getHistory(limit: number = 50): Promise<AnalysisRecord[]> {
    try {
      const res = await pool.query(
        `SELECT id, message_hash AS "messageHash", classification, risk_score AS "riskScore",
                confidence, severity, reasons, recommendation, user_action AS "userAction",
                scanned_at AS "timestamp", TRUE AS "isAiAnalyzed"
         FROM email_analysis
         ORDER BY scanned_at DESC
         LIMIT $1`,
        [limit]
      );
      return res.rows.map((row) => ({
        ...row,
        reasons: typeof row.reasons === 'string' ? JSON.parse(row.reasons) : row.reasons || [],
      }));
    } catch {
      return this.inMemoryHistory.slice(0, limit);
    }
  }

  public async getStatistics(): Promise<StatisticsData> {
    try {
      const res = await pool.query(`SELECT * FROM statistics WHERE id = 1`);
      if (res.rows.length > 0) {
        const r = res.rows[0];
        return {
          totalScanned: Number(r.total_scanned),
          safeCount: Number(r.safe_count),
          spamCount: Number(r.spam_count),
          suspiciousCount: Number(r.suspicious_count),
          highRiskCount: Number(r.high_risk_count),
          phishingCount: Number(r.phishing_count),
          reportsCount: Number(r.reports_count),
          markedSafeCount: Number(r.marked_safe_count),
        };
      }
      return this.inMemoryStats;
    } catch {
      return this.inMemoryStats;
    }
  }

  public async saveReport(messageHash: string, reportedTarget: string, notes?: string): Promise<boolean> {
    try {
      await pool.query(
        `INSERT INTO threat_reports (message_hash, reported_target, notes) VALUES ($1, $2, $3)`,
        [messageHash, reportedTarget, notes || '']
      );
      await pool.query(`UPDATE statistics SET reports_count = reports_count + 1 WHERE id = 1`);
      return true;
    } catch {
      this.inMemoryStats.reportsCount++;
      return true;
    }
  }

  public async markSafe(messageHash: string): Promise<boolean> {
    try {
      await pool.query(
        `UPDATE email_analysis SET user_action = 'MARKED_SAFE' WHERE message_hash = $1`,
        [messageHash]
      );
      await pool.query(`UPDATE statistics SET marked_safe_count = marked_safe_count + 1 WHERE id = 1`);
      return true;
    } catch {
      this.inMemoryStats.markedSafeCount++;
      const found = this.inMemoryHistory.find((item) => item.messageHash === messageHash);
      if (found) found.userAction = 'MARKED_SAFE';
      return true;
    }
  }

  public async getTrustedSenders(): Promise<string[]> {
    try {
      const res = await pool.query(`SELECT sender_or_domain FROM trusted_senders ORDER BY created_at DESC`);
      return res.rows.map((r) => r.sender_or_domain);
    } catch {
      return this.inMemoryTrusted;
    }
  }

  public async addTrustedSender(senderOrDomain: string): Promise<boolean> {
    try {
      await pool.query(
        `INSERT INTO trusted_senders (sender_or_domain) VALUES ($1) ON CONFLICT DO NOTHING`,
        [senderOrDomain.toLowerCase().trim()]
      );
      return true;
    } catch {
      if (!this.inMemoryTrusted.includes(senderOrDomain.toLowerCase().trim())) {
        this.inMemoryTrusted.push(senderOrDomain.toLowerCase().trim());
      }
      return true;
    }
  }

  public async deleteTrustedSender(senderOrDomain: string): Promise<boolean> {
    try {
      await pool.query(`DELETE FROM trusted_senders WHERE sender_or_domain = $1`, [senderOrDomain.toLowerCase().trim()]);
      return true;
    } catch {
      this.inMemoryTrusted = this.inMemoryTrusted.filter((s) => s !== senderOrDomain.toLowerCase().trim());
      return true;
    }
  }

  public async getBlockedSenders(): Promise<string[]> {
    try {
      const res = await pool.query(`SELECT sender_or_domain FROM blocked_senders ORDER BY created_at DESC`);
      return res.rows.map((r) => r.sender_or_domain);
    } catch {
      return this.inMemoryBlocked;
    }
  }

  public async addBlockedSender(senderOrDomain: string): Promise<boolean> {
    try {
      await pool.query(
        `INSERT INTO blocked_senders (sender_or_domain) VALUES ($1) ON CONFLICT DO NOTHING`,
        [senderOrDomain.toLowerCase().trim()]
      );
      return true;
    } catch {
      if (!this.inMemoryBlocked.includes(senderOrDomain.toLowerCase().trim())) {
        this.inMemoryBlocked.push(senderOrDomain.toLowerCase().trim());
      }
      return true;
    }
  }

  public async deleteBlockedSender(senderOrDomain: string): Promise<boolean> {
    try {
      await pool.query(`DELETE FROM blocked_senders WHERE sender_or_domain = $1`, [senderOrDomain.toLowerCase().trim()]);
      return true;
    } catch {
      this.inMemoryBlocked = this.inMemoryBlocked.filter((s) => s !== senderOrDomain.toLowerCase().trim());
      return true;
    }
  }

  private async incrementStats(classification: ClassificationLevel) {
    let column = 'safe_count';
    if (classification === 'SPAM') column = 'spam_count';
    if (classification === 'SUSPICIOUS') column = 'suspicious_count';
    if (classification === 'HIGH_RISK') column = 'high_risk_count';
    if (classification === 'PHISHING') column = 'phishing_count';

    await pool.query(
      `UPDATE statistics SET total_scanned = total_scanned + 1, ${column} = ${column} + 1, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
    );
  }

  private updateInMemoryStats(classification: ClassificationLevel) {
    this.inMemoryStats.totalScanned++;
    if (classification === 'SAFE') this.inMemoryStats.safeCount++;
    if (classification === 'SPAM') this.inMemoryStats.spamCount++;
    if (classification === 'SUSPICIOUS') this.inMemoryStats.suspiciousCount++;
    if (classification === 'HIGH_RISK') this.inMemoryStats.highRiskCount++;
    if (classification === 'PHISHING') this.inMemoryStats.phishingCount++;
  }
}
