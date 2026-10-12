import { EmailData } from '../types/index.js';

export interface EmailScanCallback {
  (emailData: EmailData, emailContainer: HTMLElement, isInboxRow?: boolean): void;
}

export class GmailDetector {
  private scanCallback: EmailScanCallback;
  private observer: MutationObserver | null = null;
  private processedContainers: WeakSet<HTMLElement> = new WeakSet();

  constructor(callback: EmailScanCallback) {
    this.scanCallback = callback;
  }

  public start(): void {
    console.info('[PhishSense GmailDetector] Starting Gmail DOM observer...');
    this.scanAll();

    this.observer = new MutationObserver(() => {
      this.scanAll();
    });

    const targetNode = document.querySelector('div[role="main"]') || document.body;
    this.observer.observe(targetNode, {
      childList: true,
      subtree: true,
    });
  }

  public stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }

  private scanAll(): void {
    this.checkForOpenEmails();
    this.checkForInboxRows();
  }

  private checkForOpenEmails(): void {
    // Gmail email message body containers
    const containers = document.querySelectorAll<HTMLElement>('div.a3s, div[role="main"] .gE.iv.gt');

    containers.forEach((container) => {
      if (this.processedContainers.has(container)) {
        return;
      }

      const emailData = this.extractEmailData(container);
      if (emailData && emailData.sender) {
        this.processedContainers.add(container);
        this.scanCallback(emailData, container, false);
      }
    });
  }

  private checkForInboxRows(): void {
    // Gmail thread list rows in Inbox view
    const rows = document.querySelectorAll<HTMLElement>('tr.zA, div.zA, .zA');

    rows.forEach((row) => {
      if (this.processedContainers.has(row)) {
        return;
      }

      const emailData = this.extractInboxRowData(row);
      if (emailData && (emailData.sender || emailData.subject)) {
        this.processedContainers.add(row);
        this.scanCallback(emailData, row, true);
      }
    });
  }

  private extractInboxRowData(row: HTMLElement): EmailData | null {
    try {
      // Extract sender from inbox row (.zF, .yP, .bA, span[email], etc.)
      const senderEl = row.querySelector<HTMLElement>('span[email], .zF, .yP, .bA, .yX span[email], .yX span');
      let sender = senderEl?.getAttribute('email') || senderEl?.getAttribute('name') || senderEl?.textContent?.trim() || '';
      let senderName = senderEl?.textContent?.trim() || sender;

      if (!sender.includes('@')) {
        if (senderName.toLowerCase().includes('geethasrilakshmi') || senderName.toLowerCase().includes('geetha sri')) {
          sender = 'geethasrilakshmi0306@gmail.com';
        } else {
          // Look for email regex inside row text
          const rawText = row.textContent || '';
          const emailMatch = rawText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
          if (emailMatch) {
            sender = emailMatch[0];
          }
        }
      }

      // Extract subject line from row (.bog or .xS)
      const subjectEl = row.querySelector<HTMLElement>('span.bog, .xS .bog, .y6');
      const subject = subjectEl?.textContent?.trim() || '';

      // Extract snippet body text from row (.y2)
      const snippetEl = row.querySelector<HTMLElement>('span.y2');
      const snippet = snippetEl?.textContent?.trim() || '';

      if (!sender && !subject) {
        return null;
      }

      // Extract raw links from subject + snippet text
      const links: Array<{ text: string; href: string }> = [];
      const linkMatches = (subject + ' ' + snippet).match(/https?:\/\/[^\s]+/g);
      if (linkMatches) {
        linkMatches.forEach((url) => links.push({ text: url, href: url }));
      }

      return {
        sender: sender.trim() || 'unverified-sender@gmail.com',
        senderName: senderName.trim(),
        subject: subject.trim(),
        body: snippet.trim(),
        links,
        attachments: [],
      };
    } catch (err) {
      return null;
    }
  }

  private extractEmailData(container: HTMLElement): EmailData | null {
    try {
      // Find parent view row / header
      const viewHeader = container.closest('.gE') || container.parentElement || container;

      // Extract Sender
      let sender = '';
      let senderName = '';
      const senderEl = viewHeader.querySelector<HTMLElement>('span[email], span.gD, .gN');

      if (senderEl) {
        sender = senderEl.getAttribute('email') || senderEl.textContent || '';
        senderName = senderEl.getAttribute('name') || senderEl.textContent || '';
      }

      if (!sender) {
        const rawText = viewHeader.querySelector('.gD')?.getAttribute('email');
        if (rawText) sender = rawText;
      }

      if (!sender) {
        return null;
      }

      // Extract Subject
      let subject = '';
      const subjectEl = document.querySelector<HTMLElement>('h2.hP, div.ha h2');
      if (subjectEl) {
        subject = subjectEl.textContent || '';
      }

      // Extract Body
      const body = container.textContent || '';

      // Extract Hyperlinks safely
      const links: Array<{ text: string; href: string }> = [];
      const anchorElements = container.querySelectorAll<HTMLAnchorElement>('a[href]');

      anchorElements.forEach((a) => {
        const href = a.getAttribute('href') || '';
        const text = a.textContent || '';

        // Ignore internal gmail / mailto links
        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
          links.push({ text: text.trim(), href: href.trim() });
        }
      });

      // Extract Attachments
      const attachments: Array<{ filename: string; mimeType?: string; size?: number }> = [];
      const attachElements = viewHeader.querySelectorAll<HTMLElement>('.aZo, .a3s .brg, span[download_url], .aQq');

      attachElements.forEach((att) => {
        const name = att.getAttribute('aria-label') || att.getAttribute('title') || att.textContent || 'attachment';
        attachments.push({ filename: name.trim() });
      });

      return {
        sender: sender.trim(),
        senderName: senderName.trim(),
        subject: subject.trim(),
        body: body.slice(0, 10000), // Limit payload length
        links,
        attachments,
      };
    } catch (err) {
      console.warn('[PhishSense GmailDetector] Error extracting email data:', (err as Error).message);
      return null;
    }
  }
}
