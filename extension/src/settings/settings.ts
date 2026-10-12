import { getSettings, saveSettings } from '../utils/storage.js';

document.addEventListener('DOMContentLoaded', async () => {
  const settings = await getSettings();

  const autoScanInput = document.getElementById('setting-autoScanning') as HTMLInputElement;
  const aiInput = document.getElementById('setting-aiAnalysisEnabled') as HTMLInputElement;
  const urlInput = document.getElementById('setting-urlAnalysisEnabled') as HTMLInputElement;
  const attachInput = document.getElementById('setting-attachmentAnalysisEnabled') as HTMLInputElement;
  const privacyInput = document.getElementById('setting-privacyMode') as HTMLInputElement;
  const confirmInput = document.getElementById('setting-reportConfirmation') as HTMLInputElement;

  if (autoScanInput) autoScanInput.checked = settings.autoScanning;
  if (aiInput) aiInput.checked = settings.aiAnalysisEnabled;
  if (urlInput) urlInput.checked = settings.urlAnalysisEnabled;
  if (attachInput) attachInput.checked = settings.attachmentAnalysisEnabled;
  if (privacyInput) privacyInput.checked = settings.privacyMode;
  if (confirmInput) confirmInput.checked = settings.reportConfirmation;

  let trustedSenders: string[] = settings.trustedSenders || ['google.com', 'microsoft.com'];
  let blockedSenders: string[] = settings.blockedSenders || ['scam-phish.ru'];

  const refreshTrusted = () => {
    renderChips('trusted-list-container', trustedSenders, (item) => {
      trustedSenders = trustedSenders.filter((s) => s !== item);
      refreshTrusted();
    });
  };

  const refreshBlocked = () => {
    renderChips('blocked-list-container', blockedSenders, (item) => {
      blockedSenders = blockedSenders.filter((s) => s !== item);
      refreshBlocked();
    });
  };

  refreshTrusted();
  refreshBlocked();

  document.getElementById('btn-add-trusted')?.addEventListener('click', () => {
    const input = document.getElementById('input-trusted') as HTMLInputElement;
    const val = input.value.trim().toLowerCase();
    if (val && !trustedSenders.includes(val)) {
      trustedSenders.push(val);
      input.value = '';
      refreshTrusted();
    }
  });

  document.getElementById('btn-add-blocked')?.addEventListener('click', () => {
    const input = document.getElementById('input-blocked') as HTMLInputElement;
    const val = input.value.trim().toLowerCase();
    if (val && !blockedSenders.includes(val)) {
      blockedSenders.push(val);
      input.value = '';
      refreshBlocked();
    }
  });

  document.getElementById('settings-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    await saveSettings({
      autoScanning: autoScanInput?.checked ?? true,
      aiAnalysisEnabled: aiInput?.checked ?? true,
      urlAnalysisEnabled: urlInput?.checked ?? true,
      attachmentAnalysisEnabled: attachInput?.checked ?? true,
      privacyMode: privacyInput?.checked ?? false,
      reportConfirmation: confirmInput?.checked ?? true,
      trustedSenders,
      blockedSenders,
    });

    alert('PhishSense settings saved successfully.');
  });
});

function renderChips(containerId: string, list: string[], onRemove: (item: string) => void) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = list
    .map(
      (item) => `
    <span style="display:inline-flex; align-items:center; gap:6px; background:#1f2937; border:1px solid #374151; padding:4px 10px; border-radius:16px; font-size:12px; color:#e5e7eb;">
      ${escapeHtml(item)}
      <button type="button" data-val="${escapeHtml(item)}" style="background:none; border:none; color:#ef4444; font-weight:bold; cursor:pointer;">&times;</button>
    </span>`
    )
    .join('');

  container.querySelectorAll('button[data-val]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const val = (e.currentTarget as HTMLElement).getAttribute('data-val');
      if (val) onRemove(val);
    });
  });
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
