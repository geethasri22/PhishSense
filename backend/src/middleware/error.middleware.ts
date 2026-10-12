import { Request, Response, NextFunction } from 'express';

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const errorHandler = (err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled Server Error:', err.message, err.stack);

  res.status(500).json({
    success: false,
    error: 'Internal server error occurred.',
    timestamp: new Date().toISOString(),
  });
};
