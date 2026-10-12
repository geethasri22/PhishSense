import { Router } from 'express';
import healthRoutes from './health.routes.js';
import {
  analyzeEmail,
  reportThreat,
  markSafe,
  getStatistics,
  getHistory,
} from '../controllers/analysis.controller.js';
import {
  getTrustedSenders,
  addTrustedSender,
  deleteTrustedSender,
  getBlockedSenders,
  addBlockedSender,
  deleteBlockedSender,
} from '../controllers/senders.controller.js';

const router = Router();

router.use('/health', healthRoutes);

// Email Analysis & User Feedback Routes
router.post('/analyze-email', analyzeEmail);
router.post('/report', reportThreat);
router.post('/mark-safe', markSafe);
router.get('/statistics', getStatistics);
router.get('/history', getHistory);

// Whitelist / Blacklist Senders Routes
router.get('/senders/trusted', getTrustedSenders);
router.post('/senders/trusted', addTrustedSender);
router.delete('/senders/trusted', deleteTrustedSender);

router.get('/senders/blocked', getBlockedSenders);
router.post('/senders/blocked', addBlockedSender);
router.delete('/senders/blocked', deleteBlockedSender);

export default router;

