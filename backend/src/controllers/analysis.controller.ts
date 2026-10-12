import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { RiskScoringService } from '../services/risk-scoring.service.js';
import { AiAnalysisService } from '../services/ai-analysis.service.js';
import { DatabaseService } from '../services/database.service.js';
import { ApiResponse, EmailAnalysisRequest, EmailAnalysisResponse } from '../types/index.js';
import crypto from 'crypto';

const riskScoringService = new RiskScoringService();
const aiAnalysisService = new AiAnalysisService();
const databaseService = new DatabaseService();

const EmailAnalysisSchema = z.object({
  sender: z.string().min(1, 'Sender email is required'),
  subject: z.string().default(''),
  body: z.string().default(''),
  links: z.array(z.object({ text: z.string(), href: z.string() })).default([]),
  attachments: z.array(z.object({ filename: z.string(), mimeType: z.string().optional(), size: z.number().optional() })).default([]),
  messageHash: z.string().optional(),
});

export async function analyzeEmail(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validated: EmailAnalysisRequest = EmailAnalysisSchema.parse(req.body);

    const messageHash =
      validated.messageHash ||
      crypto.createHash('sha256').update(`${validated.sender}_${validated.subject}`).digest('hex');

    // 1. Evaluate deterministic rule engine
    const ruleResult = riskScoringService.evaluateRules(validated);

    // 2. Evaluate optional AI analysis
    const aiResult = await aiAnalysisService.analyze(validated);

    // 3. Combine scores
    const finalResult = riskScoringService.combineScores(ruleResult, aiResult || undefined);

    const isAiAnalyzed = aiResult !== null;

    const responsePayload: EmailAnalysisResponse = {
      messageHash,
      classification: finalResult.classification,
      riskScore: finalResult.riskScore,
      confidence: finalResult.confidence,
      severity: finalResult.severity,
      reasons: finalResult.reasons,
      recommendation: finalResult.recommendation,
      timestamp: new Date().toISOString(),
      isAiAnalyzed,
    };

    // Save to database/memory async
    const recordId = await databaseService.saveAnalysis(responsePayload, validated.sender);
    responsePayload.id = recordId;

    const response: ApiResponse<EmailAnalysisResponse> = {
      success: true,
      data: responsePayload,
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

export async function reportThreat(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const schema = z.object({
      messageHash: z.string(),
      target: z.enum(['GMAIL', 'PHISHSENSE', 'BOTH']).default('BOTH'),
      notes: z.string().optional(),
    });

    const { messageHash, target, notes } = schema.parse(req.body);
    await databaseService.saveReport(messageHash, target, notes);

    const response: ApiResponse<{ message: string }> = {
      success: true,
      data: { message: 'Threat report submitted successfully.' },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

export async function markSafe(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const schema = z.object({ messageHash: z.string() });
    const { messageHash } = schema.parse(req.body);

    await databaseService.markSafe(messageHash);

    const response: ApiResponse<{ message: string }> = {
      success: true,
      data: { message: 'Email marked as safe.' },
      timestamp: new Date().toISOString(),
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

export async function getStatistics(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const stats = await databaseService.getStatistics();
    res.status(200).json({
      success: true,
      data: stats,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
}

export async function getHistory(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const history = await databaseService.getHistory(limit);
    res.status(200).json({
      success: true,
      data: history,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
}
