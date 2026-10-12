import { GmailDetector } from './gmail-detector.js';
import { injectSecurityBanner, injectInboxRowRedFlag } from './ui-injector.js';
import { runLocalSecurityAnalysis } from './analyzers/localEngine.js';
import { EmailData, SecurityAnalysisResult } from '../types/index.js';

console.info('[PhishSense Content Script] Loaded on Gmail page:', window.location.href);

/**
 * Detect the currently logged-in Gmail account from the page DOM.
 * Gmail renders the account avatar / profile link with the email address.
 */
function detectInboxAccount(): string {
  // Approach 1: account switcher link contains the email
  const accountLink = document.querySelector<HTMLAnchorElement>('a[href*="/u/"][aria-label*="@"]');
  if (accountLink) {
    const label = accountLink.getAttribute('aria-label') || '';
    const match = label.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
    if (match) return match[1];
  }

  // Approach 2: profile image alt attribute
  const profileImg = document.querySelector<HTMLImageElement>('img[alt][src*="googleusercontent"]');
  if (profileImg) {
    const alt = profileImg.getAttribute('alt') || '';
    const match = alt.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
    if (match) return match[1];
  }

  // Approach 3: parse /u/<n>/ from URL and look for the account data in GM_data
  try {
    // Gmail bakes the signed-in address into the page source as a JS variable
    const scripts = document.querySelectorAll<HTMLScriptElement>('script');
    for (const s of scripts) {
      const m = s.textContent?.match(/"(([a-zA-Z0-9._%+\-]+@gmail\.com))"/)?.[2];
      if (m) return m;
    }
  } catch (_) {}

  return 'unknown@gmail.com';
}

const inboxAccount = detectInboxAccount();

// Initialize Gmail Detector for both Inbox Thread List Rows and Opened Email Views
const detector = new GmailDetector((emailData: EmailData, container: HTMLElement, isInboxRow?: boolean) => {
  // Compute local security analysis immediately
  const hash = `hash_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const localAnalysis = runLocalSecurityAnalysis(emailData, hash, inboxAccount);

  if (isInboxRow) {
    // Inject Red Flag Badge and Hover Explanation listener into Inbox List row before opening
    injectInboxRowRedFlag(container, localAnalysis);
  } else {
    // Inject full Security Banner inside opened email view
    injectSecurityBanner(container, localAnalysis);
  }

  // Also query background service worker / backend for AI analysis blending if connected
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_EMAIL',
        payload: emailData,
      },
      (response) => {
        if (chrome.runtime.lastError) {
          return;
        }

        if (response && response.success && response.data) {
          const result: SecurityAnalysisResult = {
            ...response.data,
            sender: emailData.sender,
            inboxAccount,
          };
          if (isInboxRow) {
            injectInboxRowRedFlag(container, result);
          } else {
            injectSecurityBanner(container, result);
          }
        }
      }
    );
  }
});

// Start detector if on Gmail page
if (window.location.hostname.includes('mail.google.com')) {
  detector.start();
}
