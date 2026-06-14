import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';

const DB_FILE = path.join(__dirname, '../../db.json');

// Interface Declarations
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: 'Super Admin' | 'Security Administrator' | 'IT Administrator' | 'Manager' | 'Employee' | 'Guest';
  department: string;
  mfaSecret: string | null;
  mfaEnabled: boolean;
  mfaBackupCodes: string[];
  status: 'active' | 'locked' | 'suspended';
  failedLoginAttempts: number;
  lockoutUntil: string | null;
  createdAt: string;
}

export interface Device {
  id: string;
  userId: string;
  fingerprint: string;
  macHash: string;
  hostname: string;
  os: string;
  browser: string;
  diskEncryption: boolean;
  firewall: boolean;
  antivirus: boolean;
  status: 'Trusted' | 'Unknown' | 'Compromised' | 'Blocked';
  registeredAt: string;
  lastActive: string;
}

export interface Session {
  id: string;
  userId: string;
  deviceId: string | null;
  token: string;
  refreshToken: string;
  riskScore: number;
  location: {
    ip: string;
    country: string;
    city: string;
    vpn: boolean;
    tor: boolean;
  };
  userAgent: string;
  lastVerified: string;
  expiresAt: string;
  active: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  category: 'auth' | 'device' | 'gateway' | 'threat' | 'compliance';
  level: 'info' | 'warning' | 'error' | 'critical';
  userId?: string;
  userEmail?: string;
  ip: string;
  country: string;
  message: string;
  details: string;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  type: 'RBAC' | 'ABAC';
  rules: {
    roles?: string[];
    minTrustLevel?: 'Trusted' | 'Unknown';
    allowedCountries?: string[];
    maxRiskScore?: number;
    allowedTimeStart?: string; // e.g. "08:00"
    allowedTimeEnd?: string;   // e.g. "18:00"
  };
  active: boolean;
}

export interface JITRequest {
  id: string;
  userId: string;
  userEmail: string;
  resource: string;
  durationMinutes: number;
  reason: string;
  status: 'pending' | 'approved' | 'rejected';
  approvedBy?: string;
  createdAt: string;
  expiresAt?: string;
}

interface DBStructure {
  users: User[];
  devices: Device[];
  sessions: Session[];
  logs: AuditLog[];
  policies: SecurityPolicy[];
  jitRequests: JITRequest[];
}

// Default Seed Data
const DEFAULT_POLICIES: SecurityPolicy[] = [
  {
    id: 'pol-1',
    name: 'MFA Enforcement',
    description: 'Enforce Multi-Factor Authentication for all Admin and Security roles.',
    type: 'RBAC',
    rules: {
      roles: ['Super Admin', 'Security Administrator']
    },
    active: true
  },
  {
    id: 'pol-2',
    name: 'Secure Office Hours & OS Check',
    description: 'Enforce access to internal resources only from Trusted devices with disk encryption and active firewall.',
    type: 'ABAC',
    rules: {
      minTrustLevel: 'Trusted',
      maxRiskScore: 40
    },
    active: true
  },
  {
    id: 'pol-3',
    name: 'Geographic Access Restriction',
    description: 'Block resource access requests originating from blacklisted countries.',
    type: 'ABAC',
    rules: {
      allowedCountries: ['US', 'CA', 'GB', 'IN', 'DE', 'FR', 'JP', 'AU']
    },
    active: true
  }
];

class Database {
  private data: DBStructure = {
    users: [],
    devices: [],
    sessions: [],
    logs: [],
    policies: DEFAULT_POLICIES,
    jitRequests: []
  };

  constructor() {
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, 'utf-8');
        this.data = JSON.parse(fileContent);
        // Ensure default policies exist
        if (!this.data.policies || this.data.policies.length === 0) {
          this.data.policies = DEFAULT_POLICIES;
        }
      } else {
        this.seedDefaults();
      }
    } catch (error) {
      console.error('[DATABASE] Failed to load JSON database, resetting. Error:', error);
      this.seedDefaults();
    }
  }

  private seedDefaults() {
    const salt = bcrypt.genSaltSync(10);
    
    const adminUser: User = {
      id: 'usr-admin-seed',
      email: 'admin@ztna-shield.internal',
      passwordHash: bcrypt.hashSync('admin_password_101', salt),
      role: 'Super Admin',
      department: 'Security Operations',
      mfaSecret: null,
      mfaEnabled: false,
      mfaBackupCodes: ['11111111', '22222222', '33333333'],
      status: 'active',
      failedLoginAttempts: 0,
      lockoutUntil: null,
      createdAt: new Date().toISOString()
    };

    const employeeUser: User = {
      id: 'usr-employee-seed',
      email: 'employee@ztna-shield.internal',
      passwordHash: bcrypt.hashSync('employee_password_101', salt),
      role: 'Employee',
      department: 'Engineering',
      mfaSecret: null,
      mfaEnabled: false,
      mfaBackupCodes: ['44444444', '55555555', '66666666'],
      status: 'active',
      failedLoginAttempts: 0,
      lockoutUntil: null,
      createdAt: new Date().toISOString()
    };

    this.data.users = [adminUser, employeeUser];
    this.data.policies = DEFAULT_POLICIES;
    this.save();
    console.log('[DATABASE] Seed database initialized: admin@ztna-shield.internal / admin_password_101');
  }

  public save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (error) {
      console.error('[DATABASE] Failed to write to JSON database file:', error);
    }
  }

  // Database Accessors
  get users() { return this.data.users; }
  get devices() { return this.data.devices; }
  get sessions() { return this.data.sessions; }
  get logs() { return this.data.logs; }
  get policies() { return this.data.policies; }
  get jitRequests() { return this.data.jitRequests; }

  // Logging Helper
  public log(logEntry: Omit<AuditLog, 'id' | 'timestamp'>) {
    const newLog: AuditLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...logEntry
    };
    this.data.logs.unshift(newLog);
    // Keep logs size bounded (cap at 2000 logs in memory/JSON)
    if (this.data.logs.length > 2000) {
      this.data.logs = this.data.logs.slice(0, 2000);
    }
    this.save();
    console.log(`[SIEM LOG][${newLog.category.toUpperCase()}][${newLog.level.toUpperCase()}] ${newLog.message}`);
    return newLog;
  }
}

export const db = new Database();
