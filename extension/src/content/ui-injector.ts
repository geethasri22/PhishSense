import { SecurityAnalysisResult } from '../types/index.js';

export function injectSecurityBanner(container: HTMLElement, result: SecurityAnalysisResult): void {
  // Remove pre-existing banner and hover cards if present
  const existing = container.querySelector('.phishsense-security-banner');
  if (existing) {
    existing.remove();
  }

  const existingCard = document.querySelector('#phishsense-hover-card');
  if (existingCard) {
    existingCard.remove();
  }

  const banner = document.createElement('div');
  banner.className = `phishsense-security-banner phishsense-level-${result.classification.toLowerCase()}`;
  banner.setAttribute('role', 'region');
  banner.setAttribute('aria-label', 'PhishSense Security Banner');

  const config = getThemeConfig(result.classification);

  banner.innerHTML = `
    <style>
      .phishsense-security-banner {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        margin: 12px 0 16px 0;
        padding: 16px 20px;
        border-radius: 10px;
        color: #ffffff;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.18);
        background: ${config.bg};
        border-left: 6px solid ${config.border};
        transition: all 0.2s ease-in-out;
        position: relative;
      }
      .phishsense-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 10px;
      }
      .phishsense-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 0.5px;
        background: rgba(255, 255, 255, 0.2);
        backdrop-filter: blur(4px);
        cursor: pointer;
      }
      .phishsense-badge:hover {
        background: rgba(255, 255, 255, 0.35);
      }
      .phishsense-score-container {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 13px;
        font-weight: 600;
      }
      .phishsense-score-bar-bg {
        width: 100px;
        height: 8px;
        background: rgba(255, 255, 255, 0.25);
        border-radius: 4px;
        overflow: hidden;
      }
      .phishsense-score-bar-fill {
        height: 100%;
        width: ${result.riskScore}%;
        background: ${config.border};
        border-radius: 4px;
      }
      .phishsense-reasons {
        margin: 8px 0 12px 0;
        padding-left: 20px;
        font-size: 13px;
        line-height: 1.5;
        color: rgba(255, 255, 255, 0.95);
      }
      .phishsense-recommendation {
        font-size: 13px;
        font-weight: 600;
        margin-bottom: 12px;
        padding: 8px 12px;
        background: rgba(0, 0, 0, 0.18);
        border-radius: 6px;
      }
      .phishsense-hover-trigger-bar {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 10px;
        padding: 6px 10px;
        background: rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
      }
      .phishsense-hover-trigger-bar:hover {
        background: rgba(255, 255, 255, 0.22);
      }
      .phishsense-actions {
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
      }
      .phishsense-btn {
        background: #ffffff;
        color: #1f2937;
        border: none;
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.15s ease;
      }
      .phishsense-btn:hover {
        background: #f3f4f6;
      }
      .phishsense-btn-danger {
        background: #dc2626;
        color: #ffffff;
      }
      .phishsense-btn-danger:hover {
        background: #b91c1c;
      }
      .phishsense-tag {
        font-size: 11px;
        opacity: 0.85;
        margin-left: auto;
      }
    </style>

    <div class="phishsense-header">
      <div class="phishsense-badge" id="phishsense-badge-hover" title="Hover or click to view threat explanation note">
        <span>${config.icon}</span>
        <span>${config.label}</span>
      </div>
      <div class="phishsense-score-container">
        <span>Risk Score: ${result.riskScore}/100</span>
        <div class="phishsense-score-bar-bg">
          <div class="phishsense-score-bar-fill"></div>
        </div>
      </div>
    </div>

    <div class="phishsense-hover-trigger-bar" id="phishsense-explanation-trigger">
      💡 <span><strong>Hover Note:</strong> Hover over this email or click here to inspect detailed Phishing Red Flags & Safety Notes.</span>
    </div>

    <div class="phishsense-recommendation">
      🛡️ <strong>Recommendation:</strong> ${escapeHtml(result.recommendation)}
    </div>

    <ul class="phishsense-reasons">
      ${result.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}
    </ul>

    <div class="phishsense-actions">
      <button type="button" class="phishsense-btn" id="phishsense-btn-safe">✓ Mark as Safe</button>
      <button type="button" class="phishsense-btn phishsense-btn-danger" id="phishsense-btn-report">🚨 Report Phishing</button>
      <span class="phishsense-tag">${result.isAiAnalyzed ? '⚡ AI-Assisted Scan' : '🛡️ Local Rule Scan'}</span>
    </div>
  `;

  // Attach banner to DOM
  container.prepend(banner);

  // Setup Hover Card / Explanation Note Modal
  createHoverExplanationCard(result);

  // Setup Event Listeners
  const triggerBar = banner.querySelector('#phishsense-explanation-trigger');
  const badgeHover = banner.querySelector('#phishsense-badge-hover');
  const safeBtn = banner.querySelector('#phishsense-btn-safe');
  const reportBtn = banner.querySelector('#phishsense-btn-report');

  const showHoverCard = (e: Event) => {
    const card = document.getElementById('phishsense-hover-card');
    if (card && e.currentTarget) {
      card.style.display = 'block';
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      card.style.top = `${Math.min(window.innerHeight - 320, rect.bottom + window.scrollY + 6)}px`;
      card.style.left = `${Math.max(20, Math.min(window.innerWidth - 420, rect.left))}px`;
    }
  };

  const hideHoverCard = () => {
    const card = document.getElementById('phishsense-hover-card');
    if (card) {
      card.style.display = 'none';
    }
  };

  if (triggerBar) {
    triggerBar.addEventListener('mouseenter', showHoverCard);
    triggerBar.addEventListener('click', showHoverCard);
  }

  if (badgeHover) {
    badgeHover.addEventListener('mouseenter', showHoverCard);
    badgeHover.addEventListener('click', showHoverCard);
  }

  // Also listen for hover on Gmail sender elements near viewHeader
  const viewHeader = container.closest('.gE') || container.parentElement || container;
  const senderElements = viewHeader.querySelectorAll('.gD, .gN, span[email]');
  senderElements.forEach((el) => {
    el.addEventListener('mouseenter', showHoverCard);
  });

  if (safeBtn) {
    safeBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'MARK_SAFE', payload: result.messageHash }, () => {
        alert('Email marked as Safe. PhishSense security engine updated.');
        banner.remove();
        hideHoverCard();
      });
    });
  }

  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to report this email as a phishing attack?')) {
        chrome.runtime.sendMessage({ type: 'REPORT_PHISHING', payload: result.messageHash }, () => {
          alert('Phishing threat report submitted to PhishSense Security Team.');
          banner.remove();
          hideHoverCard();
        });
      }
    });
  }
}

/**
 * Injects a Red Flag Badge directly inside Gmail Inbox Thread List rows BEFORE opening the email.
 */
export function injectInboxRowRedFlag(row: HTMLElement, result: SecurityAnalysisResult): void {
  if (row.querySelector('.phishsense-inbox-flag')) {
    return;
  }

  // Only flag suspicious or phishing threats
  if (result.classification === 'SAFE' && result.riskScore < 35) {
    return;
  }

  row.style.position = 'relative';
  if (result.classification === 'PHISHING' || result.classification === 'HIGH_RISK') {
    row.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
    row.style.borderLeft = '5px solid #ef4444';
  } else if (result.classification === 'SUSPICIOUS') {
    row.style.backgroundColor = 'rgba(245, 158, 11, 0.12)';
    row.style.borderLeft = '5px solid #f59e0b';
  }

  const flagBadge = document.createElement('span');
  flagBadge.className = `phishsense-inbox-flag phishsense-inbox-level-${result.classification.toLowerCase()}`;

  const icon = result.classification === 'PHISHING' ? '🚨' : result.classification === 'HIGH_RISK' ? '⚠️' : '⚡';
  const label = result.classification === 'PHISHING' ? 'PHISHING' : result.classification;

  flagBadge.innerHTML = `
    <style>
      .phishsense-inbox-flag {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 800;
        color: #ffffff;
        background: ${result.classification === 'PHISHING' ? '#dc2626' : '#d97706'};
        margin: 0 6px;
        cursor: pointer;
        box-shadow: 0 2px 6px rgba(220, 38, 38, 0.4);
        vertical-align: middle;
        user-select: none;
        letter-spacing: 0.3px;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
      }
      .phishsense-inbox-flag:hover {
        transform: scale(1.08);
        box-shadow: 0 4px 10px rgba(220, 38, 38, 0.6);
      }
    </style>
    <span>${icon}</span>
    <span>${label} ${result.riskScore}/100</span>
  `;

  // Target where to insert the flag badge inside row (before subject .bog or .xS or .yX or sender .zF)
  const targetCol = row.querySelector('span.bog, .xS .bog, .y6, .yX, .zF, .yP') || row.firstElementChild;
  if (targetCol && targetCol.parentElement) {
    targetCol.parentElement.insertBefore(flagBadge, targetCol);
  } else {
    row.prepend(flagBadge);
  }

  // Setup Hover Event Listener on Flag Badge & Row Sender
  const showHoverCard = (e: Event) => {
    e.stopPropagation();
    let card = document.getElementById('phishsense-hover-card');
    if (!card) {
      createHoverExplanationCard(result);
      card = document.getElementById('phishsense-hover-card');
    } else {
      // Refresh content
      createHoverExplanationCard(result);
      card = document.getElementById('phishsense-hover-card');
    }
    if (card && e.currentTarget) {
      card.style.display = 'block';
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      card.style.top = `${Math.min(window.innerHeight - 340, rect.bottom + window.scrollY + 6)}px`;
      card.style.left = `${Math.max(20, Math.min(window.innerWidth - 440, rect.left))}px`;
    }
  };

  flagBadge.addEventListener('mouseenter', showHoverCard);
  flagBadge.addEventListener('click', showHoverCard);

  const senderEl = row.querySelector('.zF, .yP, .yX, span[email]');
  if (senderEl) {
    senderEl.addEventListener('mouseenter', showHoverCard);
  }
}

function createHoverExplanationCard(result: SecurityAnalysisResult): void {
  let card = document.getElementById('phishsense-hover-card');
  if (card) {
    card.remove();
  }

  card = document.createElement('div');
  card.id = 'phishsense-hover-card';
  card.style.cssText = `
    display: none;
    position: absolute;
    z-index: 999999;
    width: 380px;
    background: #0f172a;
    color: #f8fafc;
    border: 2px solid ${result.riskScore >= 60 ? '#ef4444' : '#f59e0b'};
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 12px;
    line-height: 1.5;
  `;

  card.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 10px;">
      <div style="font-weight: 700; color: #ef4444; font-size: 13px; display: flex; align-items: center; gap: 6px;">
        <span>🚨 PhishSense Threat Explanation Note</span>
      </div>
      <button id="phishsense-card-close" style="background: none; border: none; color: #94a3b8; font-weight: bold; cursor: pointer; font-size: 14px;">✕</button>
    </div>

    <div style="margin-bottom: 10px; padding: 8px; background: #1e293b; border-radius: 6px;">
      <div><strong>Scanned Inbox Account:</strong> <span style="color: #38bdf8;">${escapeHtml(result.inboxAccount || 'unknown@gmail.com')}</span></div>
      <div><strong>Flagged Sender Address:</strong> <span style="color: #f87171;">${escapeHtml(result.sender || 'unknown-sender')}</span></div>
      <div><strong>Phishing Risk Level:</strong> <span style="font-weight: bold; color: ${result.riskScore >= 60 ? '#f87171' : '#fbbf24'};"> ${result.classification} (${result.riskScore}/100)</span></div>
    </div>

    <div style="font-weight: 600; margin-bottom: 6px; color: #fbbf24;">🚩 Key Phishing Attack Red Flags Detected:</div>
    <ul style="margin: 0 0 12px 0; padding-left: 18px; color: #cbd5e1;">
      ${result.reasons.map((r) => `<li style="margin-bottom: 4px;">${escapeHtml(r)}</li>`).join('')}
    </ul>

    <div style="padding: 8px; background: #450a0a; border-left: 3px solid #ef4444; border-radius: 4px; color: #fca5a5; font-weight: 500;">
      <strong>Security Advisory:</strong> Do NOT enter passwords, click links, or reply to messages from <code>${escapeHtml(result.sender || 'this sender')}</code>.
    </div>
  `;

  document.body.appendChild(card);

  const closeBtn = card.querySelector('#phishsense-card-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      if (card) card.style.display = 'none';
    });
  }

  card.addEventListener('mouseleave', () => {
    if (card) card.style.display = 'none';
  });
}

function getThemeConfig(classification: string) {
  switch (classification) {
    case 'PHISHING':
      return { label: 'PHISHING DETECTED', icon: '🚨', bg: 'linear-gradient(135deg, #7f1d1d, #991b1b)', border: '#ef4444' };
    case 'HIGH_RISK':
      return { label: 'HIGH RISK THREAT', icon: '⚠️', bg: 'linear-gradient(135deg, #9a3412, #c2410c)', border: '#f97316' };
    case 'SUSPICIOUS':
      return { label: 'SUSPICIOUS EMAIL', icon: '⚡', bg: 'linear-gradient(135deg, #854d0e, #a16207)', border: '#f59e0b' };
    case 'SPAM':
      return { label: 'POSSIBLE SPAM', icon: '📧', bg: 'linear-gradient(135deg, #374151, #4b5563)', border: '#9ca3af' };
    case 'SAFE':
    default:
      return { label: 'EMAIL SAFE', icon: '🛡️', bg: 'linear-gradient(135deg, #065f46, #047857)', border: '#10b981' };
  }
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
