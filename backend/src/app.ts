import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import routes from './routes/index.js';
import { errorHandler } from './middleware/error.middleware.js';
import { apiLimiter } from './middleware/rate-limiter.middleware.js';
import { config } from './config/env.js';

export const createApp = (): express.Application => {
  const app = express();

  // Security Headers
  app.use(helmet());

  // CORS Config
  app.use(
    cors({
      origin: config.clientOrigin === '*' ? true : config.clientOrigin,
      credentials: true,
    })
  );

  // Rate Limiting
  app.use('/api', apiLimiter);

  // Body Parsers
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  // API Routes
  app.use('/api', routes);

  // 404 Handler
  app.use((_req, res) => {
    res.status(404).json({
      success: false,
      error: 'Endpoint not found',
      timestamp: new Date().toISOString(),
    });
  });

  // Global Error Handler
  app.use(errorHandler);

  return app;
};
