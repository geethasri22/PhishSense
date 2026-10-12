import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { DatabaseService } from '../services/database.service.js';

const databaseService = new DatabaseService();

export async function getTrustedSenders(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const list = await databaseService.getTrustedSenders();
    res.status(200).json({ success: true, data: list, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}

export async function addTrustedSender(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { senderOrDomain } = z.object({ senderOrDomain: z.string().min(1) }).parse(req.body);
    await databaseService.addTrustedSender(senderOrDomain);
    res.status(200).json({ success: true, data: { message: 'Added to trusted senders' }, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}

export async function deleteTrustedSender(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { senderOrDomain } = z.object({ senderOrDomain: z.string().min(1) }).parse(req.body);
    await databaseService.deleteTrustedSender(senderOrDomain);
    res.status(200).json({ success: true, data: { message: 'Removed from trusted senders' }, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}

export async function getBlockedSenders(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const list = await databaseService.getBlockedSenders();
    res.status(200).json({ success: true, data: list, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}

export async function addBlockedSender(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { senderOrDomain } = z.object({ senderOrDomain: z.string().min(1) }).parse(req.body);
    await databaseService.addBlockedSender(senderOrDomain);
    res.status(200).json({ success: true, data: { message: 'Added to blocked senders' }, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}

export async function deleteBlockedSender(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { senderOrDomain } = z.object({ senderOrDomain: z.string().min(1) }).parse(req.body);
    await databaseService.deleteBlockedSender(senderOrDomain);
    res.status(200).json({ success: true, data: { message: 'Removed from blocked senders' }, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
}
