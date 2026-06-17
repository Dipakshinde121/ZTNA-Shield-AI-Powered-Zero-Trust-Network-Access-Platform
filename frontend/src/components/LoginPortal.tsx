import React, { useState, useEffect, useRef } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { MouseTracker, TypingTracker } from '../utils/fingerprint';
import { Shield, Mail, Lock, Check, AlertTriangle, ArrowRight, Smartphone, RefreshCw, Globe, Code } from 'lucide-react';

interface LoginPortalProps {
  onLoginSuccess: () => void;
}

export const LoginPortal: React.FC<LoginPortalProps> = ({ onLoginSuccess }) => {
  const { simulatedDevice, setAuthData, addConsoleMessage } = useSimulation();

  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'Super Admin' | 'Security Administrator' | 'IT Administrator' | 'Manager' | 'Employee' | 'Guest'>('Employee');
  const [department, setDepartment] = useState('Engineering');
  
  // Captcha
  const [captchaSlider, setCaptchaSlider] = useState(0);
  const [isCaptchaVerified, setIsCaptchaVerified] = useState(false);
  const [captchaRequired, setCaptchaRequired] = useState(true);

  // States
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState(false);
  const [mfaUserId, setMfaUserId] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  // MFA setup states removed since they are handled in ClientPortal

  // Telemetry trackers
  const mouseTracker = useRef(new MouseTracker());
  const typingTracker = useRef(new TypingTracker());
  const loginContainerRef = useRef<HTMLDivElement>(null);

  // Start tracking mouse movements on mount inside login card
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseTracker.current.recordMove(e);
    };

    const container = loginContainerRef.current;
    if (container) {
      container.addEventListener('mousemove', handleMouseMove);
    }
    return () => {
      if (container) {
        container.removeEventListener('mousemove', handleMouseMove);
      }
    };
  }, []);

  const handleKeyPress = () => {
    typingTracker.current.recordKeyPress();
  };

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(e.target.value);
    setCaptchaSlider(value);
    if (value >= 95) {
      setIsCaptchaVerified(true);
      addConsoleMessage('CAPTCHA slider verification passed', 'success');
    }
  };

  const resetState = () => {
    setEmail('');
    setPassword('');
    setError(null);
    setCaptchaSlider(0);
    setIsCaptchaVerified(false);
    typingTracker.current.reset();
  };

  // Handles standard Login
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (captchaRequired && !isCaptchaVerified) {
      setError('Please slide to verify you are human');
      return;
    }

    setLoading(true);
    setError(null);

    // Compute browser details and behavior telemetry
    // os and browser details
    const mouseTelemetry = mouseTracker.current.getTelemetry();
    const typingTelemetry = typingTracker.current.getTelemetry();

    // Full login payload including device, location & behavior telemetry
    const payload = {
      email,
      password,
      deviceInfo: {
        fingerprint: simulatedDevice.fingerprint,
        macHash: simulatedDevice.macHash,
        hostname: simulatedDevice.hostname,
        os: simulatedDevice.os,
        browser: simulatedDevice.browser,
        diskEncryption: simulatedDevice.diskEncryption,
        firewall: simulatedDevice.firewall,
        antivirus: simulatedDevice.antivirus,
        isVPN: simulatedDevice.isVPN,
        isTor: simulatedDevice.isTor
      },
      behavior: {
        mouseVelocity: mouseTelemetry.averageVelocity,
        mouseDistance: mouseTelemetry.totalDistance,
        mouseJerk: mouseTelemetry.jerkMetric,
        typingIntervals: typingTelemetry.keyIntervals,
        typingWpm: typingTelemetry.typingSpeed
      }
    };

    addConsoleMessage(`Attempting authentication for ${email}...`, 'info');
    addConsoleMessage(`Behavioral telemetry captured. WPM: ${payload.behavior.typingWpm}, Mouse Velocity: ${payload.behavior.mouseVelocity}px/s`, 'cyber');

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const response = await fetch(`${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-mock-country': simulatedDevice.country
        },
        body: JSON.stringify(isLogin ? payload : { email, password, role, department })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (isLogin) {
        if (data.requiresMFA) {
          setMfaChallenge(true);
          setMfaUserId(data.userId);
          addConsoleMessage(`MFA validation challenge requested for User ID: ${data.userId}`, 'warn');
        } else {
          setAuthData(data.token, data.refreshToken, data.user, data.deviceStatus, data.deviceId);
          addConsoleMessage(`Session created. Device state resolved: ${data.deviceStatus}`, 'success');
          onLoginSuccess();
        }
      } else {
        // Signup success
        addConsoleMessage(`Registration approved. Email: ${email}`, 'success');
        setIsLogin(true);
        resetState();
      }
    } catch (err: any) {
      setError(err.message || 'Network error connecting to control plane');
      addConsoleMessage(`Auth Error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Handles MFA Validation Code Submission
  const handleMFASubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const payload = {
      userId: mfaUserId,
      code: mfaCode,
      deviceInfo: {
        fingerprint: simulatedDevice.fingerprint,
        macHash: simulatedDevice.macHash,
        hostname: simulatedDevice.hostname,
        os: simulatedDevice.os,
        browser: simulatedDevice.browser,
        diskEncryption: simulatedDevice.diskEncryption,
        firewall: simulatedDevice.firewall,
        antivirus: simulatedDevice.antivirus,
        isVPN: simulatedDevice.isVPN,
        isTor: simulatedDevice.isTor
      }
    };

    addConsoleMessage(`Submitting MFA challenge validation...`, 'info');

    try {
      const response = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-mock-country': simulatedDevice.country
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'MFA validation failed');
      }

      setAuthData(data.token, data.refreshToken, data.user, data.deviceStatus, data.deviceId);
      addConsoleMessage(`MFA verification approved. Session unlocked.`, 'success');
      onLoginSuccess();
    } catch (err: any) {
      setError(err.message || 'MFA verification failed');
      addConsoleMessage(`MFA Verification Error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Mock OAuth Provider Login Trigger
  const triggerMockOAuth = (provider: 'Google' | 'GitHub' | 'Microsoft') => {
    addConsoleMessage(`Initiating Single Sign-On (SSO) federated login using ${provider}...`, 'info');
    setError(null);
    setLoading(true);

    setTimeout(() => {
      // Simulate successful OAuth login returning standard corporate email
      const mockEmail = `sso.${provider.toLowerCase()}@ztna-shield.internal`;
      setEmail(mockEmail);
      setPassword('SSO-Bypass-Verified-Token-9921');
      setCaptchaRequired(false);
      setIsCaptchaVerified(true);
      setLoading(false);
      setIsLogin(true);
      addConsoleMessage(`Federated Identity verified by ${provider} OAuth. Form auto-filled.`, 'success');
    }, 1200);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] px-4" ref={loginContainerRef}>
      
      {/* Title shield decoration */}
      <div className="mb-6 flex flex-col items-center text-center">
        <div className="w-16 h-16 rounded-full bg-cyber-card border border-cyber-border flex items-center justify-center shadow-cyber-glow mb-3 animate-pulse">
          <Shield className="w-8 h-8 text-cyber-primary" />
        </div>
        <h2 className="font-mono text-2xl font-bold uppercase tracking-wider text-glow-green text-cyber-text">
          ZTNA SHIELD
        </h2>
        <p className="text-cyber-muted text-xs font-mono uppercase tracking-widest mt-1">
          Zero Trust Secure Access Gateway
        </p>
      </div>

      {/* Main card */}
      <div className="w-full max-w-md bg-cyber-card border border-cyber-border rounded-lg shadow-cyber-glow overflow-hidden scanlines">
        
        {/* Tab switch header */}
        {!mfaChallenge && (
          <div className="flex border-b border-cyber-border bg-cyber-panel font-mono text-xs uppercase tracking-wider">
            <button
              onClick={() => { setIsLogin(true); resetState(); }}
              className={`flex-1 py-3 text-center border-r border-cyber-border font-bold transition-all ${isLogin ? 'text-cyber-primary bg-cyber-card border-b-2 border-b-cyber-primary' : 'text-cyber-muted hover:text-cyber-text'}`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setIsLogin(false); resetState(); }}
              className={`flex-1 py-3 text-center font-bold transition-all ${!isLogin ? 'text-cyber-primary bg-cyber-card border-b-2 border-b-cyber-primary' : 'text-cyber-muted hover:text-cyber-text'}`}
            >
              Request Access
            </button>
          </div>
        )}

        <div className="p-6">
          {error && (
            <div className="mb-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 p-3 rounded text-xs flex items-start space-x-2 animate-bounce">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* MFA Challenge View */}
          {mfaChallenge ? (
            <form onSubmit={handleMFASubmit} className="space-y-4">
              <div className="text-center space-y-2">
                <div className="mx-auto w-12 h-12 rounded-full bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-primary shadow-cyber-glow">
                  <Smartphone className="w-6 h-6 animate-bounce" />
                </div>
                <h3 className="font-mono text-sm uppercase font-bold text-cyber-text">2FA Authentication Challenge</h3>
                <p className="text-[11px] text-cyber-muted leading-relaxed">
                  Enterprise-enforced multi-factor authentication is active on your profile. Enter the 6-digit TOTP code from your Authenticator app.
                </p>
              </div>

              <div className="space-y-2">
                <label className="block text-[10px] font-mono uppercase tracking-wider text-cyber-primary">Verification Code</label>
                <div className="relative">
                  <input
                    type="text"
                    required
                    placeholder="e.g. 123456"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2.5 rounded font-mono text-center tracking-widest text-lg focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono font-bold uppercase tracking-wider py-2.5 rounded flex items-center justify-center space-x-2 text-xs transition-colors shadow-cyber-glow hover:shadow-emerald-500/20"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <span>Verify & Unblock</span>}
              </button>

              <button
                type="button"
                onClick={() => {
                  setMfaChallenge(false);
                  setMfaUserId(null);
                  setMfaCode('');
                  addConsoleMessage('MFA Authentication challenge cancelled.', 'info');
                }}
                className="w-full text-center text-cyber-muted hover:text-cyber-text text-[10px] uppercase font-mono tracking-wider pt-2 border-t border-cyber-border"
              >
                Cancel & Sign Out
              </button>
            </form>
          ) : (
            /* Standard Login / Signup Forms */
            <form onSubmit={handleAuthSubmit} className="space-y-4">
              
              {/* Email Input */}
              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-wider text-cyber-primary">Corporate ID</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 w-4 h-4 text-cyber-muted" />
                  <input
                    type="email"
                    required
                    placeholder="email@ztna-shield.internal"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyDown={handleKeyPress}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text pl-10 pr-4 py-2 rounded text-xs focus:outline-none focus:border-cyber-primary"
                  />
                </div>
              </div>

              {/* Password Input */}
              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-wider text-cyber-primary">Security Passphrase</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 w-4 h-4 text-cyber-muted" />
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={handleKeyPress}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text pl-10 pr-4 py-2 rounded text-xs focus:outline-none focus:border-cyber-primary"
                  />
                </div>
              </div>

              {/* Signup Fields (Only visible on Access Request view) */}
              {!isLogin && (
                <div className="grid grid-cols-2 gap-3 animate-fadeIn">
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase tracking-wider text-cyber-primary">Security Role</label>
                    <select
                      value={role}
                      onChange={(e: any) => setRole(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded text-xs focus:outline-none"
                    >
                      <option value="Employee">Employee</option>
                      <option value="Manager">Manager</option>
                      <option value="IT Administrator">IT Administrator</option>
                      <option value="Security Administrator">Security Admin</option>
                      <option value="Super Admin">Super Admin</option>
                      <option value="Guest">Guest (Temporary)</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase tracking-wider text-cyber-primary">Department</label>
                    <select
                      value={department}
                      onChange={(e) => setDepartment(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded text-xs focus:outline-none"
                    >
                      <option value="Engineering">Engineering</option>
                      <option value="IT Operations">IT Ops</option>
                      <option value="Finance">Finance</option>
                      <option value="Security Operations">SecOps</option>
                      <option value="Executive Management">Executive</option>
                      <option value="Contractors">Contractors</option>
                    </select>
                  </div>
                </div>
              )}

              {/* CAPTCHA Protection */}
              {captchaRequired && isLogin && (
                <div className="bg-cyber-panel border border-cyber-border rounded p-3 space-y-2">
                  <div className="flex justify-between items-center text-[10px] font-mono uppercase tracking-wider">
                    <span className="text-cyber-muted">Human Verification Slider</span>
                    {isCaptchaVerified ? (
                      <span className="text-cyber-primary flex items-center font-bold">
                        <Check className="w-3.5 h-3.5 mr-0.5" /> VERIFIED
                      </span>
                    ) : (
                      <span className="text-amber-500 font-bold">REQUIRED</span>
                    )}
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    disabled={isCaptchaVerified}
                    value={captchaSlider}
                    onChange={handleSliderChange}
                    className={`w-full h-1.5 rounded-lg appearance-none cursor-pointer focus:outline-none ${isCaptchaVerified ? 'bg-cyber-primary' : 'bg-cyber-border'}`}
                  />
                  <p className="text-[9px] text-cyber-muted text-center italic">
                    {isCaptchaVerified ? 'Identity check verified. Proceed to authenticate.' : 'Slide fully to the right to verify browser control.'}
                  </p>
                </div>
              )}

              {/* Action Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono font-bold uppercase tracking-wider py-2.5 rounded flex items-center justify-center space-x-2 text-xs transition-colors shadow-cyber-glow hover:shadow-emerald-500/20"
              >
                {loading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <span>{isLogin ? 'Authenticate Access' : 'Create Access Request'}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

              {/* Federated SSO Mock Buttons */}
              {isLogin && (
                <div className="pt-4 border-t border-cyber-border space-y-2">
                  <p className="text-center text-[9px] font-mono text-cyber-muted uppercase tracking-widest">
                    Federated SSO login
                  </p>
                  <div className="grid grid-cols-2 gap-2 font-mono text-[9.5px]">
                    <button
                      type="button"
                      onClick={() => triggerMockOAuth('Google')}
                      className="bg-cyber-panel border border-cyber-border hover:bg-cyber-bg text-cyber-text py-2 px-3 rounded flex items-center justify-center space-x-1.5 transition-colors"
                    >
                      <Globe className="w-3 h-3 text-red-400" />
                      <span>Google Account</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => triggerMockOAuth('GitHub')}
                      className="bg-cyber-panel border border-cyber-border hover:bg-cyber-bg text-cyber-text py-2 px-3 rounded flex items-center justify-center space-x-1.5 transition-colors"
                    >
                      <Code className="w-3 h-3 text-cyber-muted" />
                      <span>GitHub Account</span>
                    </button>
                  </div>
                </div>
              )}

            </form>
          )}

        </div>
      </div>
    </div>
  );
};
