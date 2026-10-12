# PhishSense System Architecture

PhishSense is designed around a hybrid detection engine combining client-side local deterministic analysis with backend AI-powered classification and threat intelligence.

## 1. High-Level Flow Architecture

```
[ Gmail Web UI ]
       │
       ▼
[ Content Script (email-parser & gmail-detector) ]
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
[ Local Detection Engine ]       [ Service Worker ]
  - Sender Analyzer                      │
  - URL Analyzer                         ▼
  - Content Analyzer             [ PhishSense Backend ]
  - Attachment Analyzer                  │
  - Impersonation Analyzer               ├──────────────────────┐
       │                                 ▼                      ▼
       │                        [ AI Engine Client ]  [ Threat Intel Provider ]
       │                                 │                      │
       └─────────────────────────────────┴──────────────────────┘
                                 │
                                 ▼
                       [ Final Risk Engine ]
                                 │
                                 ▼
                     [ Injected Gmail Security UI ]
```

## 2. Component Breakdown

### Chrome Extension (Manifest V3)
- **Service Worker (`background/service-worker.ts`)**: Manages caching, backend REST requests, icon state updates, and extension storage.
- **Content Scripts (`content/`)**: Observes Gmail DOM changes, extracts active email details safely without script execution, injects accessible visual risk banners, and highlights suspicious URLs.
- **Popup (`popup/`)**: Quick status interface showing current email risk, scan statistics, and action links.
- **Dashboard (`dashboard/`)**: Comprehensive analytical hub featuring threat trends, recent scan records, search/filter capabilities, and metrics.
- **Settings (`settings/`)**: User preferences control panel for automatic scanning, AI analysis, privacy mode, and trusted/blocked sender lists.

### Backend (Node.js + Express + TypeScript)
- **REST Controller Layer**: Handles API requests (`/api/analyze-email`, `/api/report`, `/api/feedback`, `/api/mark-safe`, `/api/statistics`).
- **AI Analysis Service**: Securely bridges requests to Google Gemini / OpenAI, applying defensive system prompts against prompt injection.
- **Risk Scoring Aggregator**: Merges local deterministic signals (80% weight) with AI output (20% weight) to ensure deterministic security violations cannot be bypassed by raw AI responses.
- **PostgreSQL Persistence**: Stores anonymized hashes, security metadata, and aggregated metrics without saving email bodies in privacy mode.

## 3. Data Flow & Security Guarantees

1. **Email HTML Isolation**: Email content is sanitized and never executed as live DOM elements or passed into `eval`/`innerHTML`.
2. **Secret Management**: API keys and backend secrets remain exclusively on the server.
3. **Offline Fallback**: If backend services or AI API endpoints become unavailable, local security checks continue uninterrupted.
