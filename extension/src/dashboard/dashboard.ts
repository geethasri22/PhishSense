import { getStats } from '../utils/storage.js';
import { runLocalSecurityAnalysis } from '../content/analyzers/localEngine.js';
import { injectSecurityBanner } from '../content/ui-injector.js';

interface HistoryItem {
  messageHash: string;
  senderDomain?: string;
  classification: string;
  riskScore: number;
  reasons: string[];
  recommendation: string;
  timestamp: string;
  userDecision?: string;
}

document.addEventListener('DOMContentLoaded', async () => {
  const stats = await getStats();

  const totalEl = document.getElementById('dash-total');
  const safeEl = document.getElementById('dash-safe');
  const suspEl = document.getElementById('dash-suspicious');
  const phishEl = document.getElementById('dash-phishing');

  if (totalEl) totalEl.textContent = stats.totalScanned.toLocaleString();
  if (safeEl) safeEl.textContent = stats.safeCount.toLocaleString();
  if (suspEl) suspEl.textContent = stats.suspiciousCount.toLocaleString();
  if (phishEl) phishEl.textContent = stats.phishingCount.toLocaleString();

  // Load Scan History
  await loadHistory();

  // Setup Simulation Button Handler
  const simBtn = document.getElementById('btn-run-simulation');
  if (simBtn) {
    simBtn.addEventListener('click', runSimulation);
  }
});

function runSimulation() {
  const recipientInput = (document.getElementById('demo-recipient') as HTMLInputElement)?.value || 'geethasri0406@gmail.com';
  const senderInput = (document.getElementById('demo-sender') as HTMLInputElement)?.value || 'geethasrilakshmi0306@gmail.com';
  const subjectInput = (document.getElementById('demo-subject') as HTMLInputElement)?.value || 'URGENT: Verify Your Gmail Account Password Immediately';

  const outputDiv = document.getElementById('simulation-output');
  if (!outputDiv) return;

  outputDiv.style.display = 'block';
  outputDiv.innerHTML = `
    <div class="gE" style="border: 1px solid #334155; padding: 16px; border-radius: 10px; background: #020617; position: relative;">
      <div style="font-size: 13px; color: #94a3b8; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-bottom: 12px; display: flex; justify-content: space-between;">
        <div>
          <span>From: </span>
          <span class="gD" style="color: #f87171; font-weight: bold; cursor: pointer; text-decoration: underline;" title="Hover to view PhishSense threat explanation">${escapeHtml(senderInput)}</span>
        </div>
        <div>To: <span style="color: #38bdf8;">${escapeHtml(recipientInput)}</span></div>
      </div>
      <div style="font-weight: 700; font-size: 15px; color: #f8fafc; margin-bottom: 12px;">Subject: ${escapeHtml(subjectInput)}</div>
      <div id="sim-email-body" style="background: #0f172a; padding: 12px; border-radius: 6px; color: #cbd5e1; font-size: 13px;">
        <p>Dear User,</p>
        <p>Your Gmail account has been flagged for immediate security suspension due to suspicious activity. Please verify your password immediately to prevent total account termination.</p>
        <p><a href="http://192.168.1.100/verify-login?user=${encodeURIComponent(recipientInput)}" style="color: #ef4444; font-weight: bold;">[ CLICK HERE IMMEDIATELY TO VERIFY ACCOUNT PASSWORD ]</a></p>
      </div>
    </div>
  `;

  const emailData = {
    sender: senderInput,
    senderName: senderInput.split('@')[0],
    subject: subjectInput,
    body: 'Your Gmail account has been flagged for immediate security suspension due to suspicious activity. Please verify your password immediately.',
    links: [{ text: 'CLICK HERE IMMEDIATELY TO VERIFY ACCOUNT PASSWORD', href: 'http://192.168.1.100/verify-login' }],
    attachments: [],
  };

  const analysis = runLocalSecurityAnalysis(emailData, 'sim_hash_12345');
  const simContainer = outputDiv.querySelector('.gE') as HTMLElement;
  if (simContainer) {
    injectSecurityBanner(simContainer, analysis);
  }
}

async function loadHistory() {
  const tbody = document.getElementById('dash-history-body');
  if (!tbody) return;

  try {
    const res = await fetch('http://localhost:5000/api/history?limit=25');
    if (res.ok) {
      const json = await res.json();
      if (json.success && Array.isArray(json.data) && json.data.length > 0) {
        renderHistoryRows(json.data, tbody);
        return;
      }
    }
  } catch (err) {
    console.debug('[PhishSense Dashboard] Backend history endpoint unreachable:', err);
  }

  // Fallback to local storage scanned items if backend unreachable
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.get(null, (items) => {
      const records: HistoryItem[] = [];
      for (const key in items) {
        if (key.startsWith('analysis_')) {
          records.push(items[key]);
        }
      }
      records.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      if (records.length > 0) {
        renderHistoryRows(records, tbody);
      } else {
        renderEmptyHistory(tbody);
      }
    });
  } else {
    renderEmptyHistory(tbody);
  }
}

function renderEmptyHistory(tbody: HTMLElement) {
  tbody.innerHTML = `
    <tr>
      <td colspan="5" style="text-align:center; color:var(--text-secondary); padding:24px;">
        No email analysis logs recorded yet. Open emails in Gmail to populate your security history.
      </td>
    </tr>`;
}

function renderHistoryRows(items: HistoryItem[], tbody: HTMLElement) {
  tbody.innerHTML = items
    .map((item) => {
      const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Just now';
      const badgeClass = getBadgeClass(item.classification);

      return `
      <tr>
        <td style="font-size:12px; color:var(--text-secondary);">${escapeHtml(dateStr)}</td>
        <td style="font-weight:500;">
          <div>Domain / Hash</div>
          <div style="font-size:11px; color:var(--text-secondary);">${escapeHtml(item.senderDomain || item.messageHash.substring(0, 16))}</div>
        </td>
        <td style="font-weight:700;">${item.riskScore}/100</td>
        <td>
          <span style="display:inline-block; padding:4px 8px; border-radius:12px; font-size:11px; font-weight:700; ${badgeClass}">
            ${item.classification}
          </span>
        </td>
        <td style="font-size:12px;">${item.userDecision && item.userDecision !== 'NONE' ? item.userDecision : 'SCANNED'}</td>
      </tr>`;
    })
    .join('');
}

function getBadgeClass(classification: string): string {
  switch (classification) {
    case 'PHISHING':
      return 'background:#7f1d1d; color:#fca5a5;';
    case 'HIGH_RISK':
      return 'background:#7c2d12; color:#fdba74;';
    case 'SUSPICIOUS':
      return 'background:#713f12; color:#fde047;';
    case 'SPAM':
      return 'background:#374151; color:#d1d5db;';
    case 'SAFE':
    default:
      return 'background:#064e3b; color:#6ee7b7;';
  }
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
