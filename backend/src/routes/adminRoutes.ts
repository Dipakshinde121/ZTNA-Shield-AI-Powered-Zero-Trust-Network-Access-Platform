import { Router, Request, Response } from 'express';
import { verifyToken } from './authRoutes';
import { db, SecurityPolicy } from '../db';
import { PolicyEngine } from '../policy';

const router = Router();

// Middleware to restrict access to Admins only
const requireAdmin = (req: Request, res: Response, next: any) => {
  const user = (req as any).user;
  if (!user || (user.role !== 'Super Admin' && user.role !== 'Security Administrator' && user.role !== 'IT Administrator')) {
    return res.status(403).json({ error: 'Forbidden. Administrative privileges required.' });
  }
  next();
};

// Apply administrative guards to all routes in this file
router.use(verifyToken, requireAdmin);

// 1. Fetch SOC dashboard summary metrics
router.get('/metrics', (req: Request, res: Response) => {
  const activeSessions = db.sessions.filter(s => s.active);
  const registeredDevices = db.devices;
  const compromisedDevices = db.devices.filter(d => d.status === 'Compromised').length;
  const blockedDevices = db.devices.filter(d => d.status === 'Blocked').length;
  const threatLogs = db.logs.filter(l => l.category === 'threat' || l.level === 'critical');

  const totalUsers = db.users.length;
  const avgRiskScore = activeSessions.length > 0
    ? Math.round(activeSessions.reduce((sum, s) => sum + s.riskScore, 0) / activeSessions.length)
    : 0;

  res.json({
    totalUsers,
    activeSessionsCount: activeSessions.length,
    totalDevicesCount: registeredDevices.length,
    compromisedDevicesCount: compromisedDevices,
    blockedDevicesCount: blockedDevices,
    threatsBlockedCount: threatLogs.length,
    averageRiskScore: avgRiskScore
  });
});

// 2. Fetch all sessions (active and historic)
router.get('/sessions', (req: Request, res: Response) => {
  const sessionsWithDetails = db.sessions.map(s => {
    const user = db.users.find(u => u.id === s.userId);
    const device = s.deviceId ? db.devices.find(d => d.id === s.deviceId) : null;
    return {
      ...s,
      userEmail: user ? user.email : 'Unknown',
      userRole: user ? user.role : 'Guest',
      deviceHostname: device ? device.hostname : 'No device bind',
      deviceOS: device ? device.os : 'Unknown'
    };
  });
  res.json(sessionsWithDetails);
});

// Revoke a session manually (Administrators can boot users out)
router.post('/sessions/:id/revoke', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const sessionId = req.params.id;
  const session = db.sessions.find(s => s.id === sessionId);

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  session.active = false;
  db.save();

  const affectedUser = db.users.find(u => u.id === session.userId);

  db.log({
    category: 'compliance',
    level: 'warning',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `User session explicitly revoked by Admin.`,
    details: `Session ID: ${sessionId}, User affected: ${affectedUser ? affectedUser.email : 'Unknown'}, Action by: ${adminUser.email}`
  });

  res.json({ success: true, message: 'Session revoked successfully.' });
});

// 3. Fetch SIEM Audit logs with searching and filtering
router.get('/logs', (req: Request, res: Response) => {
  const query = (req.query.q as string || '').toLowerCase();
  const category = req.query.category as string || '';
  const level = req.query.level as string || '';

  let filteredLogs = db.logs;

  if (category) {
    filteredLogs = filteredLogs.filter(l => l.category === category);
  }

  if (level) {
    filteredLogs = filteredLogs.filter(l => l.level === level);
  }

  if (query) {
    filteredLogs = filteredLogs.filter(l =>
      l.message.toLowerCase().includes(query) ||
      (l.userEmail && l.userEmail.toLowerCase().includes(query)) ||
      l.ip.toLowerCase().includes(query) ||
      l.details.toLowerCase().includes(query)
    );
  }

  // Limit to 200 logs returned
  res.json(filteredLogs.slice(0, 200));
});

// 4. Policy Editor Endpoints
router.get('/policies', (req: Request, res: Response) => {
  res.json(db.policies);
});

router.post('/policies', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const { name, description, type, rules } = req.body;

  if (!name || !description || !type || !rules) {
    return res.status(400).json({ error: 'Missing policy fields.' });
  }

  const newPolicy: SecurityPolicy = {
    id: `pol-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    name,
    description,
    type,
    rules,
    active: true
  };

  db.policies.push(newPolicy);
  db.save();

  db.log({
    category: 'compliance',
    level: 'info',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `Security Policy created: ${name}`,
    details: `Type: ${type}, Created by: ${adminUser.email}`
  });

  res.json(newPolicy);
});

router.put('/policies/:id', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const policyId = req.params.id;
  const policy = db.policies.find(p => p.id === policyId);

  if (!policy) {
    return res.status(404).json({ error: 'Policy not found' });
  }

  const { name, description, rules, active } = req.body;

  if (name !== undefined) policy.name = name;
  if (description !== undefined) policy.description = description;
  if (rules !== undefined) policy.rules = rules;
  if (active !== undefined) policy.active = active;

  db.save();

  db.log({
    category: 'compliance',
    level: 'info',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `Security Policy modified: ${policy.name}`,
    details: `Active state: ${policy.active}, Modified by: ${adminUser.email}`
  });

  res.json(policy);
});

router.delete('/policies/:id', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const policyId = req.params.id;
  const policyIndex = db.policies.findIndex(p => p.id === policyId);

  if (policyIndex === -1) {
    return res.status(404).json({ error: 'Policy not found' });
  }

  const deletedPolicy = db.policies[policyIndex];
  db.policies.splice(policyIndex, 1);
  db.save();

  db.log({
    category: 'compliance',
    level: 'warning',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `Security Policy deleted: ${deletedPolicy.name}`,
    details: `Removed by: ${adminUser.email}`
  });

  res.json({ message: 'Policy deleted successfully.' });
});

// 5. Just-in-Time Access workflows
router.get('/jit-requests', (req: Request, res: Response) => {
  res.json(db.jitRequests);
});

router.put('/jit-requests/:id/approve', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const requestId = req.params.id;

  const success = PolicyEngine.approveJITRequest(requestId, adminUser.email);
  if (!success) {
    return res.status(404).json({ error: 'JIT Request not found or could not be approved' });
  }

  res.json({ message: 'JIT request approved.' });
});

router.put('/jit-requests/:id/reject', (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const requestId = req.params.id;
  const request = db.jitRequests.find(r => r.id === requestId);

  if (!request) {
    return res.status(404).json({ error: 'JIT request not found' });
  }

  request.status = 'rejected';
  db.save();

  db.log({
    category: 'compliance',
    level: 'info',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `JIT Access request rejected for ${request.userEmail}.`,
    details: `Resource: ${request.resource}, Rejected by: ${adminUser.email}`
  });

  res.json({ message: 'JIT request rejected.' });
});

export default router;
