import { Router, Request, Response } from 'express';
import { verifyToken } from './authRoutes';
import { DeviceTrustEngine } from '../device';
import { db } from '../db';

const router = Router();

// Middleware to restrict access to Admins only
const requireAdmin = (req: Request, res: Response, next: any) => {
  const user = (req as any).user;
  if (!user || (user.role !== 'Super Admin' && user.role !== 'Security Administrator' && user.role !== 'IT Administrator')) {
    return res.status(403).json({ error: 'Forbidden. Administrative privileges required.' });
  }
  next();
};

// List all devices in inventory
router.get('/', verifyToken, requireAdmin, (req: Request, res: Response) => {
  const devicesWithUsers = db.devices.map(d => {
    const user = db.users.find(u => u.id === d.userId);
    return {
      ...d,
      userEmail: user ? user.email : 'Unknown User',
      userRole: user ? user.role : 'Guest'
    };
  });
  res.json(devicesWithUsers);
});

// Update device posture status
router.put('/:id/status', verifyToken, requireAdmin, (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const deviceId = req.params.id;
  const { status } = req.body;

  if (!status || !['Trusted', 'Unknown', 'Compromised', 'Blocked'].includes(status)) {
    return res.status(400).json({ error: 'Invalid device status value.' });
  }

  const result = DeviceTrustEngine.updateDeviceStatus(deviceId, status, adminUser.email);
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }

  res.json({ message: 'Device status updated successfully.' });
});

// Revoke / delete device registration
router.delete('/:id', verifyToken, requireAdmin, (req: Request, res: Response) => {
  const adminUser = (req as any).user;
  const deviceId = req.params.id;
  const deviceIndex = db.devices.findIndex(d => d.id === deviceId);

  if (deviceIndex === -1) {
    return res.status(404).json({ error: 'Device not found' });
  }

  const device = db.devices[deviceIndex];
  db.devices.splice(deviceIndex, 1);
  db.save();

  db.log({
    category: 'compliance',
    level: 'warning',
    ip: '127.0.0.1',
    country: 'LOCAL',
    message: `Device registration revoked by Admin.`,
    details: `Device ID: ${deviceId}, Hostname: ${device.hostname}, Removed by: ${adminUser.email}`
  });

  res.json({ message: 'Device registration revoked successfully.' });
});

export default router;
