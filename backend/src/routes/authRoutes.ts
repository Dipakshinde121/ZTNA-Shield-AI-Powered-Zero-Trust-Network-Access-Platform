import { Router, Request, Response } from 'express';
import { AuthService } from '../auth';
import { DeviceTrustEngine } from '../device';
import { db } from '../db';
import jwt from 'jsonwebtoken';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'ztna-control-plane-secret-key-101';

// Middleware to protect routes and verify JWT
export const verifyToken = (req: Request, res: Response, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Token missing.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; role: string; email: string; sessionId: string };
    (req as any).user = decoded;
    
    // Check if the session is still active in DB
    const session = db.sessions.find(s => s.id === decoded.sessionId && s.active);
    if (!session) {
      return res.status(401).json({ error: 'Session has been invalidated or expired.' });
    }
    
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

router.post('/register', (req: Request, res: Response) => {
  const { email, password, role, department } = req.body;
  if (!email || !password || !role || !department) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const result = AuthService.register(email, password, role, department);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  res.status(201).json({ message: 'User registered successfully', user: result.user });
});

router.post('/login', (req: Request, res: Response) => {
  const { email, password, deviceInfo } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  // Extract mock geo-location from IP header or default (for simulator flexibility)
  const country = (req.headers['x-mock-country'] as string) || 'US';

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const loginResult = AuthService.login(email, password, ip, userAgent, country);
  if (!loginResult.success) {
    return res.status(400).json({ error: loginResult.error });
  }

  if (loginResult.requiresMFA) {
    return res.json({ requiresMFA: true, userId: loginResult.user?.id });
  }

  // Register / update device trust status
  let deviceStatus = 'Unknown';
  let deviceId = null;
  if (deviceInfo && loginResult.user) {
    const dev = DeviceTrustEngine.checkOrRegisterDevice(loginResult.user.id, {
      fingerprint: deviceInfo.fingerprint,
      macHash: deviceInfo.macHash || 'mac-hash-placeholder',
      hostname: deviceInfo.hostname || 'workstation-local',
      os: deviceInfo.os,
      browser: deviceInfo.browser,
      diskEncryption: !!deviceInfo.diskEncryption,
      firewall: !!deviceInfo.firewall,
      antivirus: !!deviceInfo.antivirus
    });
    deviceStatus = dev.status;
    deviceId = dev.id;

    // Bind session to device
    const session = db.sessions.find(s => s.token === loginResult.token);
    if (session) {
      session.deviceId = dev.id;
      session.location = {
        ip,
        country,
        city: 'Simulator Area',
        vpn: deviceInfo.isVPN || false,
        tor: deviceInfo.isTor || false
      };
      session.userAgent = userAgent;
      db.save();
    }
  }

  res.json({
    token: loginResult.token,
    refreshToken: loginResult.refreshToken,
    user: loginResult.user,
    deviceStatus,
    deviceId
  });
});

router.post('/mfa/verify', (req: Request, res: Response) => {
  const { userId, code, deviceInfo } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const country = (req.headers['x-mock-country'] as string) || 'US';

  if (!userId || !code) {
    return res.status(400).json({ error: 'User ID and verification code are required.' });
  }

  const result = AuthService.verifyMFA(userId, code, ip, country);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  const user = db.users.find(u => u.id === userId);
  let deviceStatus = 'Unknown';
  let deviceId = null;

  if (deviceInfo && user) {
    const dev = DeviceTrustEngine.checkOrRegisterDevice(user.id, {
      fingerprint: deviceInfo.fingerprint,
      macHash: deviceInfo.macHash || 'mac-hash-placeholder',
      hostname: deviceInfo.hostname || 'workstation-local',
      os: deviceInfo.os,
      browser: deviceInfo.browser,
      diskEncryption: !!deviceInfo.diskEncryption,
      firewall: !!deviceInfo.firewall,
      antivirus: !!deviceInfo.antivirus
    });
    deviceStatus = dev.status;
    deviceId = dev.id;

    // Bind session to device
    const session = db.sessions.find(s => s.token === result.token);
    if (session) {
      session.deviceId = dev.id;
      session.location = {
        ip,
        country,
        city: 'Simulator Area',
        vpn: deviceInfo.isVPN || false,
        tor: deviceInfo.isTor || false
      };
      session.userAgent = req.headers['user-agent'] || '';
      db.save();
    }
  }

  const { passwordHash: _, ...userWithoutHash } = user!;

  res.json({
    token: result.token,
    refreshToken: result.refreshToken,
    user: userWithoutHash,
    deviceStatus,
    deviceId
  });
});

router.post('/mfa/enable/step1', verifyToken, (req: Request, res: Response) => {
  const user = (req as any).user;
  const result = AuthService.enableMFAStep1(user.userId);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  res.json({ secret: result.secret, qrString: result.qrString });
});

router.post('/mfa/enable/step2', verifyToken, (req: Request, res: Response) => {
  const user = (req as any).user;
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Code is required.' });
  }

  const result = AuthService.enableMFAStep2(user.userId, code);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  res.json({ message: 'MFA enabled successfully.', backupCodes: result.backupCodes });
});

router.post('/refresh', (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const country = (req.headers['x-mock-country'] as string) || 'US';

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required.' });
  }

  const result = AuthService.refreshToken(refreshToken, ip, country);
  if (!result.success) {
    return res.status(401).json({ error: result.error });
  }

  res.json({ token: result.token, refreshToken: result.refreshToken });
});

router.post('/logout', verifyToken, (req: Request, res: Response) => {
  const user = (req as any).user;
  const session = db.sessions.find(s => s.id === user.sessionId);
  if (session) {
    session.active = false;
    db.save();
    
    db.log({
      category: 'auth',
      level: 'info',
      userId: user.userId,
      userEmail: user.email,
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: 'User logged out, session terminated.',
      details: `Session ID: ${user.sessionId}`
    });
  }
  res.json({ success: true, message: 'Logged out successfully.' });
});

export default router;
