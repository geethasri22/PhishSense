# PhishSense — AI-Powered Phishing & Spam Detection Chrome Extension

> **Think Before You Click.**

PhishSense is a production-quality, AI-assisted cybersecurity Chrome Extension for Gmail. It automatically inspects incoming emails for security threats including phishing, spam, credential harvesting, impersonation, look-alike domains, and suspicious attachments.

---

## 🌟 Key Features

- **Hybrid Detection Architecture**: Combines local client-side deterministic analysis with backend AI security classification.
- **Gmail Web Integration**: Automatically detects opened email messages and highlights security indicators inside Gmail.
- **Explainable Risk Scoring**: Generates a 0–100 risk score with human-understandable evidence-based reasons.
- **Accessible Color & Text Alerts**: Uses clear labels (`SAFE`, `SUSPICIOUS`, `HIGH RISK`, `PHISHING`) with high-contrast color indicators and icons.
- **Privacy First**: Optional strict privacy mode ensuring email subjects and body text never leave the user's browser.
- **Offline & Fallback Safety**: Operates seamlessly via local deterministic rules if backend or AI endpoints are unavailable.

---

## 📁 Repository Structure

```
PhishSense/
├── package.json               # Root workspace launcher
├── .env.example               # Environment variables configuration template
├── .gitignore                 # Git ignore rules
├── README.md                  # Main documentation
├── extension/                 # Chrome Extension (Manifest V3)
│   ├── manifest.json          # Manifest V3 setup
│   ├── package.json           # Extension dependencies
│   ├── vite.config.ts         # Bundler config
│   ├── tsconfig.json          # TypeScript configuration
│   ├── src/
│   │   ├── background/        # Service Worker
│   │   ├── content/           # Content script for Gmail DOM
│   │   ├── popup/             # Extension Toolbar Popup
│   │   ├── dashboard/         # Full Security Dashboard
│   │   ├── settings/          # User Preferences & Privacy Settings
│   │   ├── types/             # Shared TypeScript types
│   │   └── utils/             # Chrome Storage & Hash utilities
│   └── assets/icons/          # Extension PNG icons (16, 48, 128px)
├── backend/                   # Node.js + Express Backend API
│   ├── package.json           # Backend dependencies
│   ├── tsconfig.json          # TypeScript config
│   ├── src/
│   │   ├── server.ts          # Server entry point
│   │   ├── app.ts             # Express app middleware & routes
│   │   ├── config/            # Environment variable validation
│   │   ├── controllers/       # Health & Analysis controllers
│   │   ├── database/          # PostgreSQL pool setup
│   │   ├── middleware/        # Rate limiter & global error handler
│   │   └── routes/            # API endpoints
│   └── tests/
├── database/
│   └── schema/
│       └── schema.sql         # PostgreSQL schema (users, analysis, reports, stats)
└── docs/
    └── architecture.md        # Deep architectural design document
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites

- Node.js (v18.x or higher)
- npm (v9.x or higher)
- PostgreSQL (v14.x or higher)

### 2. Environment Configuration

Copy `.env.example` to `.env` in the root workspace directory:

```bash
cp .env.example .env
```

### 3. Installation

Install all root, extension, and backend dependencies:

```bash
npm run setup
```

### 4. Database Setup

Execute the schema script against your PostgreSQL instance:

```bash
psql -U postgres -d phishsense -f database/schema/schema.sql
```

### 5. Start Backend Server

```bash
npm run dev:backend
```

The backend server will run on `http://localhost:5000`. Test health status at:
`http://localhost:5000/api/health`

### 6. Build Chrome Extension

```bash
npm run build:extension
```

The compiled extension output will be placed in `extension/dist`.

### 7. Load Extension into Chrome

1. Open Google Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `d:\PhishSense\extension\dist` directory
5. The **PhishSense** icon will appear in your extensions bar!
