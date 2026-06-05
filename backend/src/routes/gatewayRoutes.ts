import { Router, Request, Response } from 'express';
import { verifyToken } from './authRoutes';
import { db } from '../db';
import { DeviceTrustEngine } from '../device';
import { RiskAssessmentEngine } from '../risk';
import { PolicyEngine } from '../policy';

const router = Router();

// Helper to extract device headers sent by the frontend simulator
const getDeviceContext = (req: Request) => {
  return {
    fingerprint: (req.headers['x-device-fingerprint'] as string) || 'default-fingerprint',
    macHash: (req.headers['x-device-mac'] as string) || 'a1:b2:c3:d4:e5:f6',
    hostname: (req.headers['x-device-hostname'] as string) || 'unknown-workstation',
    os: (req.headers['x-device-os'] as string) || 'Unknown OS',
    browser: (req.headers['x-device-browser'] as string) || 'Unknown Browser',
    diskEncryption: req.headers['x-device-encryption'] === 'true',
    firewall: req.headers['x-device-firewall'] === 'true',
    antivirus: req.headers['x-device-antivirus'] === 'true',
    isVPN: req.headers['x-device-vpn'] === 'true',
    isTor: req.headers['x-device-tor'] === 'true'
  };
};

// Continuous Authentication Session Status Check
router.get('/session-status', verifyToken, (req: Request, res: Response) => {
  const tokenUser = (req as any).user;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const country = (req.headers['x-mock-country'] as string) || 'US';
  
  const user = db.users.find(u => u.id === tokenUser.userId);
  if (!user) {
    return res.status(401).json({ status: 'blocked', reason: 'User profile not found' });
  }

  // Extract simulated device state
  const deviceContext = getDeviceContext(req);
  
  // Re-run Device Trust Engine check
  const device = DeviceTrustEngine.checkOrRegisterDevice(user.id, deviceContext);

  // Re-run AI Risk Assessment
  const riskResult = RiskAssessmentEngine.evaluate(
    user,
    deviceContext,
    null, // no new typing behavior telemetry on polling
    ip,
    country
  );

  // Update session record in DB
  const session = db.sessions.find(s => s.id === tokenUser.sessionId);
  if (session) {
    session.riskScore = riskResult.riskScore;
    session.deviceId = device.id;
    session.lastVerified = new Date().toISOString();
    
    // Bind location
    session.location = {
      ip,
      country,
      city: 'Simulator Location',
      vpn: deviceContext.isVPN,
      tor: deviceContext.isTor
    };
    db.save();
  }

  // Evaluate Policies
  const policyResult = PolicyEngine.evaluateAccess(
    user,
    device,
    riskResult.riskScore,
    country,
    'session-keepalive'
  );

  if (!policyResult.allowed) {
    if (session) {
      session.active = false; // Kill session
      db.save();
    }
    
    db.log({
      category: 'threat',
      level: 'critical',
      userId: user.id,
      userEmail: user.email,
      ip,
      country,
      message: `Continuous Auth Poll: Session terminated dynamically due to security violations.`,
      details: policyResult.reason || 'Unknown policy violation'
    });

    return res.json({
      status: 'blocked',
      reason: policyResult.reason
    });
  }

  res.json({
    status: 'valid',
    riskScore: riskResult.riskScore,
    riskLevel: riskResult.riskLevel,
    riskDetails: riskResult.details,
    deviceStatus: device.status
  });
});

// Protected Resource Gateway Proxy Endpoints
router.get('/access/:resource', verifyToken, (req: Request, res: Response) => {
  const tokenUser = (req as any).user;
  const resource = req.params.resource;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const country = (req.headers['x-mock-country'] as string) || 'US';

  const user = db.users.find(u => u.id === tokenUser.userId);
  if (!user) {
    return res.status(401).json({ error: 'User profile not found' });
  }

  // Check for SQL Injection signature in query parameters, body, or headers
  const rawParams = JSON.stringify({ ...req.query, ...req.body, resource });
  const sqlInjectionPattern = /('|--|#|\bUNION\b|\bSELECT\b|\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?)/i;
  if (sqlInjectionPattern.test(decodeURIComponent(rawParams))) {
    db.log({
      category: 'threat',
      level: 'critical',
      userId: user.id,
      userEmail: user.email,
      ip,
      country,
      message: `WAF Rule Intercept: SQL Injection attempt blocked on resource [${resource.toUpperCase()}]`,
      details: `Injected payload detected: "${rawParams.substring(0, 150)}..."`
    });

    return res.status(403).json({
      error: 'Access denied. Web Application Firewall (WAF) detected a SQL injection signature in request parameters.'
    });
  }

  // Extract device headers and check trust
  const deviceContext = getDeviceContext(req);
  const device = DeviceTrustEngine.checkOrRegisterDevice(user.id, deviceContext);

  // Evaluate Risk Score
  const riskResult = RiskAssessmentEngine.evaluate(user, deviceContext, null, ip, country);

  // Evaluate security policy
  const policyResult = PolicyEngine.evaluateAccess(
    user,
    device,
    riskResult.riskScore,
    country,
    resource
  );

  // Update session
  const session = db.sessions.find(s => s.id === tokenUser.sessionId);
  if (session) {
    session.riskScore = riskResult.riskScore;
    session.lastVerified = new Date().toISOString();
    db.save();
  }

  if (!policyResult.allowed) {
    db.log({
      category: 'gateway',
      level: 'warning',
      userId: user.id,
      userEmail: user.email,
      ip,
      country,
      message: `Gateway Blocked: Unauthorized access attempt to protected resource [${resource.toUpperCase()}]`,
      details: policyResult.reason || 'Policy rule block'
    });

    return res.status(403).json({
      error: policyResult.reason || 'Access denied by ZTNA policies.'
    });
  }

  // Log successful access
  db.log({
    category: 'gateway',
    level: 'info',
    userId: user.id,
    userEmail: user.email,
    ip,
    country,
    message: `Gateway Allowed: Access granted to protected resource [${resource.toUpperCase()}]`,
    details: `Session Risk Score: ${riskResult.riskScore}. Device Status: ${device.status}`
  });

  // Provide mock payload representing protected enterprise databases
  let payload: any = null;

  if (resource === 'payroll') {
    payload = [
      { id: 1, name: 'Alice Adams', department: 'Engineering', salary: '$145,000', securityLevel: 'Tier 2' },
      { id: 2, name: 'Bob Baker', department: 'SecOps', salary: '$165,000', securityLevel: 'Tier 3' },
      { id: 3, name: 'Charlie Clark', department: 'Finance', salary: '$110,000', securityLevel: 'Tier 1' },
      { id: 4, name: 'Dana Davis', department: 'IT Operations', salary: '$130,000', securityLevel: 'Tier 2' }
    ];
  } else if (resource === 'ssh') {
    payload = {
      message: 'SSH tunnel opened successfully to target database.',
      host: 'db-prod-cluster.internal',
      port: 22,
      fingerprint: 'SHA256:ZTNA-GATEWAY-SSH-KEY-SIMULATED-449102-SECURE',
      encryption: 'AES-256-GCM',
      sessionBegan: new Date().toISOString()
    };
  } else if (resource === 'api') {
    payload = {
      gatewayVersion: '1.42-release',
      loadBalancerStatus: 'ONLINE',
      activeProxyNodes: 4,
      securityPoliciesEnforced: db.policies.length,
      currentBlocklistLength: db.devices.filter(d => d.status === 'Blocked').length,
      activeSessionsLogged: db.sessions.filter(s => s.active).length
    };
  }

  res.json({
    success: true,
    payload
  });
});

// Submit JIT Access Request
router.post('/jit-request', verifyToken, (req: Request, res: Response) => {
  const tokenUser = (req as any).user;
  const { resource, durationMinutes, reason } = req.body;

  if (!resource || !durationMinutes || !reason) {
    return res.status(400).json({ error: 'Missing required JIT access fields' });
  }

  const user = db.users.find(u => u.id === tokenUser.userId);
  if (!user) {
    return res.status(401).json({ error: 'User profile not found' });
  }

  const newRequest = PolicyEngine.createJITRequest(
    user.id,
    user.email,
    resource,
    parseInt(durationMinutes),
    reason
  );

  res.json({
    success: true,
    message: 'JIT access request submitted successfully. Awaiting SecOps review.',
    request: newRequest
  });
});

export default router;
