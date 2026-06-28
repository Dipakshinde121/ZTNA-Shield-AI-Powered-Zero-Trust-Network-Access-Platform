import { db, Device } from './db';

export class DeviceTrustEngine {
  /**
   * Evaluates a device's security posture and categorizes it
   */
  static evaluatePosture(posture: {
    diskEncryption: boolean;
    firewall: boolean;
    antivirus: boolean;
    os: string;
    browser: string;
  }): { status: Device['status']; riskPenalty: number } {
    let riskPenalty = 0;
    
    // Check compromise indicators
    if (!posture.antivirus) {
      riskPenalty += 30;
    }
    if (!posture.firewall) {
      riskPenalty += 20;
    }
    if (!posture.diskEncryption) {
      riskPenalty += 15;
    }

    // OS Vulnerability check
    const isOutdatedOS = posture.os.toLowerCase().includes('windows 7') || 
                         posture.os.toLowerCase().includes('windows xp') ||
                         posture.os.toLowerCase().includes('mac os x 10.11');
    if (isOutdatedOS) {
      riskPenalty += 40;
      return { status: 'Compromised', riskPenalty };
    }

    // Browser check
    if (posture.browser.toLowerCase().includes('ie ') || posture.browser.toLowerCase().includes('internet explorer')) {
      riskPenalty += 25;
      return { status: 'Compromised', riskPenalty };
    }

    if (riskPenalty >= 40) {
      return { status: 'Compromised', riskPenalty };
    } else if (riskPenalty > 0) {
      // Missing some security settings but not completely compromised
      return { status: 'Unknown', riskPenalty };
    }

    return { status: 'Trusted', riskPenalty: 0 };
  }

  /**
   * Registers or updates a device record
   */
  static checkOrRegisterDevice(userId: string, info: {
    fingerprint: string;
    macHash: string;
    hostname: string;
    os: string;
    browser: string;
    diskEncryption: boolean;
    firewall: boolean;
    antivirus: boolean;
  }): Device {
    let device = db.devices.find(d => d.fingerprint === info.fingerprint && d.userId === userId);
    
    const { status: calculatedStatus, riskPenalty } = this.evaluatePosture(info);

    if (device) {
      // Update existing device posture and active timestamp
      device.lastActive = new Date().toISOString();
      device.diskEncryption = info.diskEncryption;
      device.firewall = info.firewall;
      device.antivirus = info.antivirus;
      device.os = info.os;
      device.browser = info.browser;
      
      // If device is compromised or blocked, maintain that status, otherwise update based on posture
      if (device.status !== 'Blocked') {
        device.status = calculatedStatus;
      }
      
      db.save();
      return device;
    }

    // Register new device
    device = {
      id: `dev-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      userId,
      fingerprint: info.fingerprint,
      macHash: info.macHash,
      hostname: info.hostname,
      os: info.os,
      browser: info.browser,
      diskEncryption: info.diskEncryption,
      firewall: info.firewall,
      antivirus: info.antivirus,
      status: calculatedStatus,
      registeredAt: new Date().toISOString(),
      lastActive: new Date().toISOString()
    };

    db.devices.push(device);
    db.save();

    db.log({
      category: 'device',
      level: device.status === 'Compromised' ? 'error' : 'info',
      userId,
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `New device registered. Status determined as ${device.status}.`,
      details: `OS: ${device.os}, Hostname: ${device.hostname}, Disk Encrypted: ${device.diskEncryption}`
    });

    return device;
  }

  /**
   * Administrators manually updating a device's trust level
   */
  static updateDeviceStatus(deviceId: string, status: Device['status'], adminUserEmail: string): { success: boolean; error?: string } {
    const device = db.devices.find(d => d.id === deviceId);
    if (!device) {
      return { success: false, error: 'Device not found' };
    }

    const oldStatus = device.status;
    device.status = status;
    db.save();

    db.log({
      category: 'compliance',
      level: 'info',
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `Device status manually modified to ${status} by Admin.`,
      details: `Device ID: ${deviceId}, Hostname: ${device.hostname}, Old Status: ${oldStatus}, Action by: ${adminUserEmail}`
    });

    return { success: true };
  }
}
