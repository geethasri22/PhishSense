import { SecurityAnalysisResult, EmailData, SecurityStats } from '../types/index.js';
import { getSettings, getCachedAnalysis, saveCachedAnalysis, getStats, updateStats } from '../utils/storage.js';
import { runLocalSecurityAnalysis } from '../content/analyzers/localEngine.js';

console.info('[PhishSense Background] Service Worker initialized.');

chrome.runtime.onInstalled.addListener(() => {
  console.info('[PhishSense Background] Extension installed successfully.');
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    handleEmailAnalysis(message.payload)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // async channel open
  }

  if (message.type === 'MARK_SAFE') {
    handleMarkSafe(message.payload)
      .then((res) => sendResponse({ success: true, data: res }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'REPORT_PHISHING') {
    handleReportPhishing(message.payload)
      .then((res) => sendResponse({ success: true, data: res }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_STATS') {
    getStats().then((stats) => sendResponse({ success: true, data: stats }));
    return true;
  }

  if (message.type === 'GET_SETTINGS') {
    getSettings().then((settings) => sendResponse({ success: true, data: settings }));
    return true;
  }

  return false;
});

async function handleEmailAnalysis(emailData: EmailData): Promise<SecurityAnalysisResult> {
  const hash = await generateHash(`${emailData.sender}_${emailData.subject}`);
  const cached = await getCachedAnalysis(hash);

  if (cached) {
    console.info('[PhishSense Background] Cache hit for hash:', hash);
    updateBadge(cached.classification);
    return cached;
  }

  const settings = await getSettings();
  let analysisResult: SecurityAnalysisResult | null = null;

  // Try backend API scan first
  try {
    const backendUrl = 'http://localhost:5000/api/analyze-email';
    const payload = settings.privacyMode
      ? { sender: emailData.sender, subject: emailData.subject, links: [], attachments: [], body: '' }
      : emailData;

    const resp = await fetch(backendUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (resp.ok) {
      const json = (await resp.json()) as { success?: boolean; data?: SecurityAnalysisResult };
      if (json.success && json.data) {
        analysisResult = json.data;
      }
    }
  } catch (err) {
    console.warn('[PhishSense Background] Backend API offline/unreachable. Falling back to local engine.', (err as Error).message);
  }

  // Fallback to local rule engine if backend is offline or failed
  if (!analysisResult) {
    analysisResult = runLocalSecurityAnalysis(emailData, hash);
  }

  await saveCachedAnalysis(hash, analysisResult);

  // Update statistics
  const currentStats = await getStats();
  const statUpdate: Partial<SecurityStats> = { totalScanned: currentStats.totalScanned + 1 };
  if (analysisResult.classification === 'SAFE') statUpdate.safeCount = currentStats.safeCount + 1;
  if (analysisResult.classification === 'SPAM') statUpdate.spamCount = currentStats.spamCount + 1;
  if (analysisResult.classification === 'SUSPICIOUS') statUpdate.suspiciousCount = currentStats.suspiciousCount + 1;
  if (analysisResult.classification === 'HIGH_RISK') statUpdate.highRiskCount = currentStats.highRiskCount + 1;
  if (analysisResult.classification === 'PHISHING') statUpdate.phishingCount = currentStats.phishingCount + 1;

  await updateStats(statUpdate);
  updateBadge(analysisResult.classification);

  return analysisResult;
}

async function handleMarkSafe(hash: string): Promise<boolean> {
  const cached = await getCachedAnalysis(hash);
  if (cached) {
    cached.userDecision = 'MARKED_SAFE';
    cached.classification = 'SAFE';
    cached.riskScore = 0;
    cached.recommendation = 'User marked this email as safe.';
    await saveCachedAnalysis(hash, cached);
  }

  const currentStats = await getStats();
  await updateStats({ markedSafeCount: currentStats.markedSafeCount + 1 });

  try {
    await fetch('http://localhost:5000/api/mark-safe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageHash: hash }),
    });
  } catch (err) {
    console.debug('[PhishSense Background] Sync mark-safe endpoint error:', err);
  }

  return true;
}

async function handleReportPhishing(hash: string): Promise<boolean> {
  const cached = await getCachedAnalysis(hash);
  if (cached) {
    cached.userDecision = 'REPORTED';
    cached.classification = 'PHISHING';
    cached.riskScore = 100;
    await saveCachedAnalysis(hash, cached);
  }

  const currentStats = await getStats();
  await updateStats({ reportsCount: currentStats.reportsCount + 1 });

  try {
    await fetch('http://localhost:5000/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageHash: hash, target: 'BOTH' }),
    });
  } catch (err) {
    console.debug('[PhishSense Background] Sync report endpoint error:', err);
  }

  return true;
}

function updateBadge(classification: string) {
  if (classification === 'PHISHING' || classification === 'HIGH_RISK') {
    chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
    chrome.action.setBadgeText({ text: 'ALERT' });
  } else if (classification === 'SUSPICIOUS' || classification === 'SPAM') {
    chrome.action.setBadgeBackgroundColor({ color: '#F59E0B' });
    chrome.action.setBadgeText({ text: 'WARN' });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: '#10B981' });
    chrome.action.setBadgeText({ text: 'OK' });
  }
}

async function generateHash(input: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
