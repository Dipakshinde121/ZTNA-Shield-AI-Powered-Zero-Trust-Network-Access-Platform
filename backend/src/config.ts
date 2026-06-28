import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

// Resolve paths to support running from root or backend directory
const backendEnvPath = path.join(__dirname, '../.env');
const rootEnvPath = path.join(__dirname, '../../../.env');

if (fs.existsSync(backendEnvPath)) {
  dotenv.config({ path: backendEnvPath });
} else if (fs.existsSync(rootEnvPath)) {
  dotenv.config({ path: rootEnvPath });
} else {
  // Fallback to default behavior
  dotenv.config();
}

const jwtSecret = process.env.JWT_SECRET;
const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;

// Fail fast: Throw error if crucial security environment variables are missing
if (!jwtSecret || jwtSecret.trim() === '') {
  throw new Error(
    '[FATAL CONFIG ERROR] JWT_SECRET is not defined in the environment variables.\n' +
    'Please ensure you have a .env file configured with a secure JWT_SECRET.'
  );
}

if (!jwtRefreshSecret || jwtRefreshSecret.trim() === '') {
  throw new Error(
    '[FATAL CONFIG ERROR] JWT_REFRESH_SECRET is not defined in the environment variables.\n' +
    'Please ensure you have a .env file configured with a secure JWT_REFRESH_SECRET.'
  );
}

export const JWT_SECRET = jwtSecret;
export const JWT_REFRESH_SECRET = jwtRefreshSecret;
export const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 5000;
export const NODE_ENV = process.env.NODE_ENV || 'development';
