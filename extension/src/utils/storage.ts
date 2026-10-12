import { UserSettings, SecurityStats, SecurityAnalysisResult } from '../types/index.js';

const DEFAULT_SETTINGS: UserSettings = {
  autoScanning: true,
  aiAnalysisEnabled: true,
  urlAnalysisEnabled: true,
  attachmentAnalysisEnabled: true,
  showWarnings: true,
  showExplanations: true,
  reportConfirmation: true,
  privacyMode: false,
  trustedSenders: [],
  blockedSenders: [],
};

const DEFAULT_STATS: SecurityStats = {
  totalScanned: 0,
  safeCount: 0,
  spamCount: 0,
  suspiciousCount: 0,
  highRiskCount: 0,
  phishingCount: 0,
  reportsCount: 0,
  markedSafeCount: 0,
};

const isChromeStorageAvailable = (): boolean => {
  return typeof chrome !== 'undefined' && Boolean(chrome.storage);
};

export const getSettings = async (): Promise<UserSettings> => {
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.sync) {
      try {
        const local = localStorage.getItem('phishsense_settings');
        resolve(local ? JSON.parse(local) : DEFAULT_SETTINGS);
      } catch {
        resolve(DEFAULT_SETTINGS);
      }
      return;
    }
    chrome.storage.sync.get(['settings'], (result) => {
      resolve(result?.settings || DEFAULT_SETTINGS);
    });
  });
};

export const saveSettings = async (settings: Partial<UserSettings>): Promise<UserSettings> => {
  const current = await getSettings();
  const updated = { ...current, ...settings };
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.sync) {
      try {
        localStorage.setItem('phishsense_settings', JSON.stringify(updated));
      } catch {
        // ignore
      }
      resolve(updated);
      return;
    }
    chrome.storage.sync.set({ settings: updated }, () => {
      resolve(updated);
    });
  });
};

export const getStats = async (): Promise<SecurityStats> => {
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.local) {
      try {
        const local = localStorage.getItem('phishsense_stats');
        resolve(local ? JSON.parse(local) : DEFAULT_STATS);
      } catch {
        resolve(DEFAULT_STATS);
      }
      return;
    }
    chrome.storage.local.get(['stats'], (result) => {
      resolve(result?.stats || DEFAULT_STATS);
    });
  });
};

export const updateStats = async (update: Partial<SecurityStats>): Promise<SecurityStats> => {
  const current = await getStats();
  const updated = { ...current, ...update };
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.local) {
      try {
        localStorage.setItem('phishsense_stats', JSON.stringify(updated));
      } catch {
        // ignore
      }
      resolve(updated);
      return;
    }
    chrome.storage.local.set({ stats: updated }, () => {
      resolve(updated);
    });
  });
};

export const saveCachedAnalysis = async (hash: string, analysis: SecurityAnalysisResult): Promise<void> => {
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.local) {
      try {
        localStorage.setItem(`phishsense_analysis_${hash}`, JSON.stringify(analysis));
      } catch {
        // ignore
      }
      resolve();
      return;
    }
    chrome.storage.local.set({ [`analysis_${hash}`]: analysis }, () => {
      resolve();
    });
  });
};

export const getCachedAnalysis = async (hash: string): Promise<SecurityAnalysisResult | null> => {
  return new Promise((resolve) => {
    if (!isChromeStorageAvailable() || !chrome.storage.local) {
      try {
        const local = localStorage.getItem(`phishsense_analysis_${hash}`);
        resolve(local ? JSON.parse(local) : null);
      } catch {
        resolve(null);
      }
      return;
    }
    chrome.storage.local.get([`analysis_${hash}`], (result) => {
      resolve(result?.[`analysis_${hash}`] || null);
    });
  });
};
