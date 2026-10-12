import { getStats } from '../utils/storage.js';

document.addEventListener('DOMContentLoaded', async () => {
  const stats = await getStats();

  const scannedEl = document.getElementById('stat-scanned');
  const threatsEl = document.getElementById('stat-threats');
  const phishingEl = document.getElementById('stat-phishing');
  const suspiciousEl = document.getElementById('stat-suspicious');

  if (scannedEl) scannedEl.textContent = stats.totalScanned.toLocaleString();
  if (threatsEl) threatsEl.textContent = (stats.phishingCount + stats.suspiciousCount + stats.highRiskCount).toLocaleString();
  if (phishingEl) phishingEl.textContent = stats.phishingCount.toLocaleString();
  if (suspiciousEl) suspiciousEl.textContent = stats.suspiciousCount.toLocaleString();

  document.getElementById('btn-open-dashboard')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/dashboard/dashboard.html') });
  });

  document.getElementById('btn-open-settings')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/settings/settings.html') });
  });
});
