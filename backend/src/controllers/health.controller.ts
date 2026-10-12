import { Request, Response } from 'express';

export const getHealthStatus = (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    data: {
      status: 'UP',
      service: 'PhishSense Backend API',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    },
    timestamp: new Date().toISOString(),
  });
};
