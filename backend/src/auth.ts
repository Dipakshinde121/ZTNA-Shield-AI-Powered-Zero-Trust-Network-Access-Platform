import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db, User, Session } from './db';

const JWT_SECRET = process.env.JWT_SECRET || 'ztna-control-plane-secret-key-101';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'ztna-refresh-token-secret-key-101';
const LOCKOUT_LIMIT = 5;
const LOCKOUT_WINDOW_MINUTES = 10;

// Simple simulation of TOTP (RFC 6238)
// Returns a 6-digit string based on seed & current 30s epoch interval
export function generateTOTPCode(secret: string): string {
  const timeIndex = Math.floor(Date.now() / 30000);
  const hash = (timeIndex * secret.length).toString();
  let code = '';
  for (let i = 0; i < 6; i++) {
    const charCode = hash.charCodeAt((i + secret.length) % hash.length) || 48;
    code += (charCode % 10).toString();
  }
  return code;
}

export class AuthService {
  /**
   * Registers a new user
   */
  static register(email: string, passwordRaw: string, role: User['role'], department: string): { success: boolean; user?: Omit<User, 'passwordHash'>; error?: string } {
    const exists = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (exists) {
      return { success: false, error: 'User already exists' };
    }

    if (passwordRaw.length < 8) {
      return { success: false, error: 'Password must be at least 8 characters long' };
    }

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(passwordRaw, salt);

    const newUser: User = {
      id: `usr-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      email: email.toLowerCase(),
      passwordHash,
      role,
      department,
      mfaSecret: null,
      mfaEnabled: false,
      mfaBackupCodes: Array.from({ length: 5 }, () => Math.floor(10000000 + Math.random() * 90000000).toString()),
      status: 'active',
      failedLoginAttempts: 0,
      lockoutUntil: null,
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    db.save();

    db.log({
      category: 'auth',
      level: 'info',
      userId: newUser.id,
      userEmail: newUser.email,
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `User registered successfully with role ${role}`,
      details: `Department: ${department}`
    });

    const { passwordHash: _, ...userWithoutHash } = newUser;
    return { success: true, user: userWithoutHash };
  }

  /**
   * Standard Username/Password Login Route
   */
  static login(email: string, passwordRaw: string, ip: string, userAgent: string, country: string): { success: boolean; requiresMFA?: boolean; token?: string; refreshToken?: string; user?: Omit<User, 'passwordHash'>; error?: string } {
    const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return { success: false, error: 'Invalid credentials' };
    }

    // Check account lockout
    if (user.status === 'locked' && user.lockoutUntil) {
      const lockTime = new Date(user.lockoutUntil).getTime();
      if (Date.now() < lockTime) {
        db.log({
          category: 'auth',
          level: 'warning',
          userId: user.id,
          userEmail: user.email,
          ip,
          country,
          message: `Blocked login attempt. Account locked.`,
          details: `Attempts: ${user.failedLoginAttempts}`
        });
        return { success: false, error: `Account locked. Please try again after ${new Date(lockTime).toLocaleTimeString()}` };
      } else {
        // Lockout expired
        user.status = 'active';
        user.failedLoginAttempts = 0;
        user.lockoutUntil = null;
        db.save();
      }
    }

    const passwordMatch = bcrypt.compareSync(passwordRaw, user.passwordHash);
    if (!passwordMatch) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= LOCKOUT_LIMIT) {
        user.status = 'locked';
        const lockoutTime = new Date();
        lockoutTime.setMinutes(lockoutTime.getMinutes() + LOCKOUT_WINDOW_MINUTES);
        user.lockoutUntil = lockoutTime.toISOString();
        db.log({
          category: 'threat',
          level: 'critical',
          userId: user.id,
          userEmail: user.email,
          ip,
          country,
          message: `Account locked due to brute force protection.`,
          details: `Threshold exceeded: ${LOCKOUT_LIMIT} attempts.`
        });
      } else {
        db.save();
      }
      return { success: false, error: 'Invalid credentials' };
    }

    // Reset failed login tracking
    user.failedLoginAttempts = 0;
    user.lockoutUntil = null;
    db.save();

    // Check if MFA is required
    if (user.mfaEnabled) {
      return { success: true, requiresMFA: true, user: { id: user.id, email: user.email, role: user.role, department: user.department } as any };
    }

    // Issue standard tokens
    const tokens = this.issueTokens(user, null);

    db.log({
      category: 'auth',
      level: 'info',
      userId: user.id,
      userEmail: user.email,
      ip,
      country,
      message: `User logged in successfully without MFA`,
      details: `User agent: ${userAgent}`
    });

    const { passwordHash: _, ...userWithoutHash } = user;
    return { success: true, token: tokens.token, refreshToken: tokens.refreshToken, user: userWithoutHash };
  }

  /**
   * Completes MFA challenge validation
   */
  static verifyMFA(userId: string, code: string, ip: string, country: string): { success: boolean; token?: string; refreshToken?: string; error?: string } {
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      return { success: false, error: 'MFA is not enabled for this user' };
    }

    const calculatedCode = generateTOTPCode(user.mfaSecret);
    const backupMatchIndex = user.mfaBackupCodes.indexOf(code);

    if (code !== calculatedCode && backupMatchIndex === -1) {
      db.log({
        category: 'auth',
        level: 'warning',
        userId: user.id,
        userEmail: user.email,
        ip,
        country,
        message: `MFA validation failed. Incorrect code entered.`,
        details: `Entered code: ${code}`
      });
      return { success: false, error: 'Invalid MFA verification code' };
    }

    // If backup code used, remove it
    if (backupMatchIndex !== -1) {
      user.mfaBackupCodes.splice(backupMatchIndex, 1);
      db.save();
    }

    const tokens = this.issueTokens(user, null);

    db.log({
      category: 'auth',
      level: 'info',
      userId: user.id,
      userEmail: user.email,
      ip,
      country,
      message: `MFA validation passed. Authorized session created.`,
      details: backupMatchIndex !== -1 ? 'Backup code used' : 'TOTP used'
    });

    return { success: true, token: tokens.token, refreshToken: tokens.refreshToken };
  }

  /**
   * Generates a temporary secret for QR code configuration
   */
  static enableMFAStep1(userId: string): { success: boolean; secret?: string; qrString?: string; error?: string } {
    const user = db.users.find(u => u.id === userId);
    if (!user) return { success: false, error: 'User not found' };

    const secret = `secret-${Math.random().toString(36).substr(2, 12).toUpperCase()}`;
    user.mfaSecret = secret;
    db.save();

    // Standard TOTP QR enrollment format
    const qrString = `otpauth://totp/ZTNA-Shield:${user.email}?secret=${secret}&issuer=ZTNA-Shield`;
    return { success: true, secret, qrString };
  }

  /**
   * Verifies & locks in user's initial MFA secret
   */
  static enableMFAStep2(userId: string, code: string): { success: boolean; backupCodes?: string[]; error?: string } {
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.mfaSecret) return { success: false, error: 'MFA setup not initialized' };

    const calculated = generateTOTPCode(user.mfaSecret);
    if (code !== calculated) {
      return { success: false, error: 'Incorrect verification code. Please try again.' };
    }

    user.mfaEnabled = true;
    db.save();

    db.log({
      category: 'auth',
      level: 'info',
      userId: user.id,
      userEmail: user.email,
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `Multi-Factor Authentication enabled.`,
      details: `Method: TOTP`
    });

    return { success: true, backupCodes: user.mfaBackupCodes };
  }

  /**
   * Refreshes access tokens using Token Rotation strategy
   */
  static refreshToken(oldRefreshToken: string, ip: string, country: string): { success: boolean; token?: string; refreshToken?: string; error?: string } {
    try {
      const decoded = jwt.verify(oldRefreshToken, JWT_REFRESH_SECRET) as { userId: string; sessionId: string };
      const session = db.sessions.find(s => s.id === decoded.sessionId && s.active);

      if (!session) {
        // Potential Token Abuse or Session Hijacking
        db.log({
          category: 'threat',
          level: 'critical',
          ip,
          country,
          message: `Refresh token theft/abuse detected. Session invalidated.`,
          details: `Session ID: ${decoded.sessionId}`
        });
        return { success: false, error: 'Session expired or token abused' };
      }

      const user = db.users.find(u => u.id === session.userId);
      if (!user || user.status !== 'active') {
        session.active = false;
        db.save();
        return { success: false, error: 'Account disabled' };
      }

      // Rotate tokens
      const newTokens = this.issueTokens(user, session.id);
      
      // Update session record
      session.token = newTokens.token;
      session.refreshToken = newTokens.refreshToken;
      session.lastVerified = new Date().toISOString();
      db.save();

      return { success: true, token: newTokens.token, refreshToken: newTokens.refreshToken };
    } catch (e) {
      return { success: false, error: 'Invalid refresh token' };
    }
  }

  /**
   * Internal Helper to create JWTs and Database Sessions
   */
  private static issueTokens(user: User, existingSessionId: string | null): { token: string; refreshToken: string } {
    const sessionId = existingSessionId || `ses-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
    
    const token = jwt.sign(
      { userId: user.id, role: user.role, email: user.email, sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user.id, sessionId },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    if (!existingSessionId) {
      const newSession: Session = {
        id: sessionId,
        userId: user.id,
        deviceId: null,
        token,
        refreshToken,
        riskScore: 0,
        location: {
          ip: '127.0.0.1',
          country: 'LOCAL',
          city: 'LOCAL',
          vpn: false,
          tor: false
        },
        userAgent: '',
        lastVerified: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        active: true
      };
      db.sessions.push(newSession);
      db.save();
    }

    return { token, refreshToken };
  }
}
