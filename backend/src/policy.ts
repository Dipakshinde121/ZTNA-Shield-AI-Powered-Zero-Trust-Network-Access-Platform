import { db, User, Device, SecurityPolicy, JITRequest } from './db';

export class PolicyEngine {
  /**
   * Evaluates security policies for an access request
   */
  static evaluateAccess(
    user: User,
    device: Device | null,
    riskScore: number,
    country: string,
    resource: string
  ): { allowed: boolean; reason?: string } {
    
    // 1. Check if user account is disabled or locked
    if (user.status !== 'active') {
      return { allowed: false, reason: `Account state is suspended or locked. Current status: ${user.status}` };
    }

    // 2. Check for device-specific blocks
    if (device && device.status === 'Blocked') {
      return { allowed: false, reason: 'Endpoint device is explicitly blacklisted by Security Administrator.' };
    }
    if (device && device.status === 'Compromised') {
      return { allowed: false, reason: 'Endpoint device failed baseline configuration tests. Antivirus deactivated or outdated OS version.' };
    }

    // 3. Evaluate Active Policies in database
    const activePolicies = db.policies.filter(p => p.active);

    for (const policy of activePolicies) {
      const { rules } = policy;

      // A. Role check (RBAC)
      // If the policy is role-specific and the user is NOT in the allowed roles list
      if (rules.roles && rules.roles.length > 0) {
        if (!rules.roles.includes(user.role)) {
          // Check if user has an active Just-in-Time approved request bypassing this constraint
          const hasJIT = this.checkJITAccess(user.id, resource);
          if (!hasJIT) {
            return { 
              allowed: false, 
              reason: `RBAC Policy violation [${policy.name}]: Access requires roles: [${rules.roles.join(', ')}]. Current role: ${user.role}.` 
            };
          }
        }
      }

      // B. Device Trust Level check (ABAC)
      if (rules.minTrustLevel === 'Trusted') {
        if (!device || device.status !== 'Trusted') {
          // Check if JIT access bypass is active
          const hasJIT = this.checkJITAccess(user.id, resource);
          if (!hasJIT) {
            return { 
              allowed: false, 
              reason: `ABAC Policy violation [${policy.name}]: Access requires verified posture with "Trusted" state. Current device state: ${device ? device.status : 'Unregistered'}.` 
            };
          }
        }
      }

      // C. Country whitelist check (ABAC)
      if (rules.allowedCountries && rules.allowedCountries.length > 0) {
        if (!rules.allowedCountries.includes(country)) {
          return { 
            allowed: false, 
            reason: `ABAC Policy violation [${policy.name}]: Access from geographic region [${country}] is restricted by location baseline policies.` 
          };
        }
      }

      // D. Session Risk Score check (ABAC)
      if (rules.maxRiskScore !== undefined) {
        if (riskScore > rules.maxRiskScore) {
          return { 
            allowed: false, 
            reason: `ABAC Policy violation [${policy.name}]: Session anomaly risk score (${riskScore}) exceeds maximum permissible policy threshold (${rules.maxRiskScore}).` 
          };
        }
      }

      // E. Work Hours time constraint (ABAC)
      if (rules.allowedTimeStart && rules.allowedTimeEnd) {
        const now = new Date();
        const currentHour = now.getHours();
        const currentMinute = now.getMinutes();
        
        const [startHour, startMin] = rules.allowedTimeStart.split(':').map(Number);
        const [endHour, endMin] = rules.allowedTimeEnd.split(':').map(Number);
        
        const currentMins = currentHour * 60 + currentMinute;
        const startMins = startHour * 60 + startMin;
        const endMins = endHour * 60 + endMin;

        if (currentMins < startMins || currentMins > endMins) {
          // Guest roles should be strictly blocked out of hours
          if (user.role === 'Guest') {
            return {
              allowed: false,
              reason: `ABAC Policy violation [${policy.name}]: Access hours restricted between ${rules.allowedTimeStart} and ${rules.allowedTimeEnd}.`
            };
          }
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Helper to verify if JIT (Just-In-Time) access exists and is approved/valid
   */
  private static checkJITAccess(userId: string, resource: string): boolean {
    const now = new Date();
    const jit = db.jitRequests.find(r => 
      r.userId === userId && 
      r.resource.toLowerCase() === resource.toLowerCase() && 
      r.status === 'approved' &&
      r.expiresAt && new Date(r.expiresAt).getTime() > now.getTime()
    );
    
    if (jit) {
      console.log(`[POLICY] JIT Access Bypass validated for User ${userId} on Resource ${resource}. Expires at: ${jit.expiresAt}`);
      return true;
    }
    
    return false;
  }

  /**
   * Requests Just-In-Time access
   */
  static createJITRequest(
    userId: string,
    userEmail: string,
    resource: string,
    durationMinutes: number,
    reason: string
  ): JITRequest {
    const newRequest: JITRequest = {
      id: `jit-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      userId,
      userEmail,
      resource,
      durationMinutes,
      reason,
      status: 'pending',
      createdAt: new Date().toISOString()
    };

    db.jitRequests.push(newRequest);
    db.save();

    db.log({
      category: 'gateway',
      level: 'warning',
      userId,
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `JIT Access requested for ${resource} by ${userEmail}`,
      details: `Duration: ${durationMinutes} mins, Reason: ${reason}`
    });

    return newRequest;
  }

  /**
   * Approves JIT access request
   */
  static approveJITRequest(requestId: string, adminEmail: string): boolean {
    const request = db.jitRequests.find(r => r.id === requestId);
    if (!request) return false;

    request.status = 'approved';
    request.approvedBy = adminEmail;
    
    const expires = new Date();
    expires.setMinutes(expires.getMinutes() + request.durationMinutes);
    request.expiresAt = expires.toISOString();
    
    db.save();

    db.log({
      category: 'compliance',
      level: 'info',
      ip: '127.0.0.1',
      country: 'LOCAL',
      message: `JIT request approved for ${request.userEmail}.`,
      details: `Resource: ${request.resource}, Approved by: ${adminEmail}, Expires: ${request.expiresAt}`
    });

    return true;
  }
}
