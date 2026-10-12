import { createApp } from './app.js';
import { config } from './config/env.js';

const app = createApp();

const server = app.listen(config.port, () => {
  console.info(`[PhishSense Backend] Server running on port ${config.port} in ${config.nodeEnv} mode`);
});

const gracefulShutdown = (signal: string) => {
  console.info(`[PhishSense Backend] Received ${signal}. Shutting down gracefully...`);
  server.close(() => {
    console.info('[PhishSense Backend] Closed active connections.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
