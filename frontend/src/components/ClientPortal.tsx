import React, { useState, useEffect, useRef } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { ztnaFetch } from '../utils/api';
import { Shield, Key, Terminal, Database, Server, Smartphone, RefreshCw, AlertOctagon, Activity, ShieldAlert, Zap, Send, ShieldCheck, Check } from 'lucide-react';

export const ClientPortal: React.FC = () => {
  const { token, user, deviceStatus, simulatedDevice, updateSimulatedDevice, setAuthData, logout, addConsoleMessage } = useSimulation();

  const [activeSubTab, setActiveSubTab] = useState<'access' | 'lab'>('access');

  const [mfaSecret, setMfaSecret] = useState('');
  // mfaQrString removed to fix unused warning
  const [mfaCode, setMfaCode] = useState('');
  const [mfaEnabledUser, setMfaEnabledUser] = useState(false);
  const [mfaSetupActive, setMfaSetupActive] = useState(false);
  const [mfaBackupCodes, setMfaBackupCodes] = useState<string[]>([]);
  const [copiedCodes, setCopiedCodes] = useState(false);

  // Protected Resources Simulation states
  const [activeResource, setActiveResource] = useState<'payroll' | 'ssh' | 'api' | null>(null);
  const [resourceContent, setResourceContent] = useState<string | null>(null);
  const [resourceError, setResourceError] = useState<string | null>(null);
  const [loadingResource, setLoadingResource] = useState(false);

  // SSH Interactive Terminal inputs
  const [sshCommand, setSshCommand] = useState('');
  const [sshTerminalOutput, setSshTerminalOutput] = useState<string[]>([
    'ZTNA Secure SSH Gateway v1.42',
    'Continuous session validation active.',
    'Type "help" for available commands.'
  ]);

  // Continuous Authentication polling states
  const [isPolling, setIsPolling] = useState(false);
  const [pollRiskScore, setPollRiskScore] = useState<number>(0);
  const [pollRiskLevel, setPollRiskLevel] = useState<string>('Low');
  const [pollRiskDetails, setPollRiskDetails] = useState<string[]>([]);

  // JIT access request form
  const [jitResource, setJitResource] = useState('payroll');
  const [jitDuration, setJitDuration] = useState('15');
  const [jitReason, setJitReason] = useState('');
  const [jitStatusMsg, setJitStatusMsg] = useState<string | null>(null);

  // SQL Injection Lab states
  const [sqlDept, setSqlDept] = useState('');
  const [sqliResult, setSqliResult] = useState<any>(null);
  const [sqliError, setSqliError] = useState<string | null>(null);
  const [sqliLoading, setSqliLoading] = useState(false);

  // Brute Force Lab states
  const [bruteForceLogs, setBruteForceLogs] = useState<string[]>([]);
  const [bruteForceLoading, setBruteForceLoading] = useState(false);

  // Prevent multiple parallel polls
  const pollingRef = useRef(false);

  // Continuous Authentication Polling Loop (polls every 5 seconds)
  useEffect(() => {
    if (!token) return;

    const performPoll = async () => {
      if (pollingRef.current) return;
      pollingRef.current = true;
      setIsPolling(true);

      try {
        const response = await ztnaFetch('/api/gateway/session-status', 'GET', simulatedDevice, token);
        const data = await response.json();

        if (data.status === 'blocked') {
          addConsoleMessage(`Continuous Auth: Session revoked! Reason: ${data.reason}`, 'error');
          alert(`[ZTNA BLOCK] Session revoked by Gateway. Reason: ${data.reason}`);
          setAuthData(null, null, null, 'Unknown', null);
          logout();
          return;
        }

        // Update local session stats
        setPollRiskScore(data.riskScore);
        setPollRiskLevel(data.riskLevel);
        setPollRiskDetails(data.riskDetails || []);
        
        // Update device status in parent context
        if (data.deviceStatus) {
          setAuthData(token, localStorage.getItem('ztna_refresh'), user, data.deviceStatus, localStorage.getItem('ztna_device_id') || '');
        }

      } catch (e) {
        console.error('Continuous Authentication poll failed:', e);
      } finally {
        setIsPolling(false);
        pollingRef.current = false;
      }
    };

    // Run initial poll
    performPoll();

    // Set interval for continuous checks
    const interval = setInterval(performPoll, 5000);
    return () => clearInterval(interval);
  }, [token, simulatedDevice]);

  // Initiate MFA setup step 1
  const startMFASetup = async () => {
    if (!token) return;
    setLoadingResource(true);
    addConsoleMessage('Initiating multi-factor enrollment step 1...', 'info');

    try {
      const response = await ztnaFetch('/api/auth/mfa/enable/step1', 'POST', simulatedDevice, token);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      setMfaSecret(data.secret);
      setMfaSetupActive(true);
      addConsoleMessage('TOTP enrollment secret generated.', 'success');
    } catch (e: any) {
      addConsoleMessage(`MFA setup failed: ${e.message}`, 'error');
    } finally {
      setLoadingResource(false);
    }
  };

  // Lock in MFA setup step 2
  const confirmMFASetup = async () => {
    if (!token || !mfaCode) return;
    setLoadingResource(true);
    addConsoleMessage('Confirming TOTP validation code...', 'info');

    try {
      const response = await ztnaFetch('/api/auth/mfa/enable/step2', 'POST', simulatedDevice, token, { code: mfaCode });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      setMfaBackupCodes(data.backupCodes || []);
      setMfaEnabledUser(true);
      setMfaSetupActive(false);
      addConsoleMessage('MFA successfully enabled and locked to identity.', 'success');
    } catch (e: any) {
      addConsoleMessage(`MFA verification failed: ${e.message}`, 'error');
      alert(e.message);
    } finally {
      setLoadingResource(false);
    }
  };

  // Accessing Simulated Internal Resources
  const accessResource = async (resource: 'payroll' | 'ssh' | 'api') => {
    setActiveResource(resource);
    setLoadingResource(true);
    setResourceError(null);
    setResourceContent(null);
    addConsoleMessage(`Gateway intercepting request for resource: ${resource.toUpperCase()}`, 'info');

    try {
      const response = await ztnaFetch(`/api/gateway/access/${resource}`, 'GET', simulatedDevice, token);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Access denied by security policies');
      }

      setResourceContent(data.payload);
      addConsoleMessage(`Access granted for resource: ${resource.toUpperCase()}`, 'success');
    } catch (e: any) {
      setResourceError(e.message);
      addConsoleMessage(`Gateway Block: Access denied to ${resource.toUpperCase()}. Reason: ${e.message}`, 'error');
    } finally {
      setLoadingResource(false);
    }
  };

  // Submit JIT request
  const submitJITRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !jitReason.trim()) return;

    try {
      const response = await ztnaFetch('/api/gateway/jit-request', 'POST', simulatedDevice, token, {
        resource: jitResource,
        durationMinutes: parseInt(jitDuration),
        reason: jitReason
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);

      setJitStatusMsg(data.message);
      setJitReason('');
      addConsoleMessage(`JIT access request submitted successfully. Target: ${jitResource.toUpperCase()}`, 'success');
      setTimeout(() => setJitStatusMsg(null), 5000);
    } catch (e: any) {
      alert(e.message);
    }
  };

  // Execute SQL Injection exploit request
  const runSQLiExploit = async () => {
    setSqliLoading(true);
    setSqliError(null);
    setSqliResult(null);
    addConsoleMessage('Executing SQLi exploit attempt on payroll node...', 'warn');

    try {
      // Pass sqlDept in query parameters which gets caught by backend WAF regex
      const response = await ztnaFetch(`/api/gateway/access/payroll?dept=${encodeURIComponent(sqlDept)}`, 'GET', simulatedDevice, token);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Request Blocked');
      }

      setSqliResult(data.payload);
      addConsoleMessage('SQLi Exploit request completed: returned data!', 'success');
    } catch (e: any) {
      setSqliError(e.message);
      addConsoleMessage(`WAF Block: SQLi request blocked. ${e.message}`, 'error');
    } finally {
      setSqliLoading(false);
    }
  };

  // Trigger Brute Force Lockout Flooder
  const runBruteForceFlood = async () => {
    setBruteForceLoading(true);
    setBruteForceLogs([]);
    addConsoleMessage('Triggering brute force flood simulator...', 'warn');

    let logsCollector: string[] = [];
    const updateLogs = (msg: string) => {
      logsCollector.push(msg);
      setBruteForceLogs([...logsCollector]);
    };

    try {
      for (let i = 1; i <= 6; i++) {
        updateLogs(`[Attempt ${i}/6] Sending incorrect login payload for: ${user?.email}...`);
        
        const response = await fetch('http://localhost:5000/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: user?.email, password: 'wrong-passphrase-9999' })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          updateLogs(`[SUCCESS?] Unexpected login success.`);
        } else {
          updateLogs(`[FAILED] Server reply: "${data.error}"`);
        }

        // Delay slightly between requests
        await new Promise(r => setTimeout(r, 400));
      }

      updateLogs(`[SYSTEM] Flooder completed. Triggering continuous authentication check...`);
      addConsoleMessage('Brute force simulation flood completed.', 'success');
    } catch (e: any) {
      updateLogs(`[ERROR] Request failed: ${e.message}`);
    } finally {
      setBruteForceLoading(false);
    }
  };

  const executeSshCommand = (e: React.FormEvent) => {
    e.preventDefault();
    if (!sshCommand.trim()) return;

    const cmd = sshCommand.toLowerCase().trim();
    let reply = `Command "${sshCommand}" executed.`;

    if (cmd === 'help') {
      reply = 'Available commands: help, whoami, secrets, get_logs, logout';
    } else if (cmd === 'whoami') {
      reply = `Authenticated as: ${user?.email} (Role: ${user?.role})`;
    } else if (cmd === 'secrets') {
      reply = 'Database passwords: [DECRYPTED] production_db_key = $3kr3t_ztn4_pa$$';
    } else if (cmd === 'get_logs') {
      reply = 'System stats: cpu=12%, memory=4.2GB/8.0GB, requests=104/s';
    } else if (cmd === 'logout') {
      reply = 'Closing SSH connection...';
      setTimeout(() => setActiveResource(null), 1000);
    }

    setSshTerminalOutput(prev => [...prev, `$ ${sshCommand}`, reply]);
    setSshCommand('');
  };

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      
      {/* Top Welcome Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col md:flex-row md:items-center justify-between shadow-cyber-glow animate-fadeIn">
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 rounded bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-primary shadow-cyber-glow">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h3 className="font-mono text-sm font-bold text-cyber-text">{user?.email}</h3>
            <div className="flex items-center space-x-2 mt-1">
              <span className="bg-cyber-panel text-cyber-primary text-[10px] font-mono px-2 py-0.5 rounded border border-cyber-border uppercase font-semibold">
                {user?.role}
              </span>
              <span className="text-[10px] text-cyber-muted font-mono">{user?.department || 'IT Operations'}</span>
            </div>
          </div>
        </div>
        
        {/* Device Posture Display */}
        <div className="mt-4 md:mt-0 flex items-center space-x-3 bg-cyber-panel border border-cyber-border rounded p-3 text-xs">
          <span className="text-cyber-muted font-mono flex items-center">
            Continuous Auth Check:
            <Activity className={`w-3.5 h-3.5 ml-1 text-cyber-primary ${isPolling ? 'animate-pulse text-emerald-400' : 'text-cyber-muted'}`} />
          </span>
          <span className="text-cyber-muted font-mono border-l border-cyber-border pl-3">Device State:</span>
          {deviceStatus === 'Trusted' && (
            <span className="text-emerald-400 font-bold flex items-center">
              <ShieldCheck className="w-3.5 h-3.5 mr-1" /> TRUSTED
            </span>
          )}
          {deviceStatus === 'Unknown' && (
            <span className="text-amber-400 font-bold flex items-center">
              <AlertOctagon className="w-3.5 h-3.5 mr-1" /> UNKNOWN
            </span>
          )}
          {deviceStatus === 'Compromised' && (
            <span className="text-rose-400 font-bold flex items-center">
              <AlertOctagon className="w-3.5 h-3.5 mr-1" /> COMPROMISED
            </span>
          )}
          {deviceStatus === 'Blocked' && (
            <span className="text-red-500 font-bold flex items-center">
              <AlertOctagon className="w-3.5 h-3.5 mr-1" /> BLOCKED
            </span>
          )}
          <button onClick={logout} className="text-rose-400 hover:text-rose-300 font-mono text-[10px] uppercase font-bold border-l border-cyber-border pl-3 ml-1">
            Disconnect
          </button>
        </div>
      </div>

      {/* Internal Navigation Subtabs */}
      <div className="flex border-b border-cyber-border font-mono text-xs uppercase tracking-wider space-x-2">
        <button
          onClick={() => setActiveSubTab('access')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeSubTab === 'access' ? 'bg-cyber-card text-cyber-secondary font-bold' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Access Intranet
        </button>
        <button
          onClick={() => setActiveSubTab('lab')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeSubTab === 'lab' ? 'bg-cyber-card text-cyber-primary font-bold' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          SecOps Attack & JIT Lab
        </button>
      </div>

      {/* SUBTAB 1: ACCESS INTRANET (Original Content) */}
      {activeSubTab === 'access' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fadeIn">
          {/* Left column: MFA settings & Continuous Risk Diagnostics */}
          <div className="md:col-span-1 space-y-6">
            {/* Continuous Threat Diagnostics Panel */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-primary border-b border-cyber-border pb-2 flex items-center justify-between">
                <span className="flex items-center"><Activity className="w-4 h-4 mr-1.5" /> Threat Telemetry</span>
                <span className={`text-[10px] px-1 py-0.5 rounded font-mono ${pollRiskLevel === 'Low' ? 'bg-emerald-500/10 text-emerald-400' : pollRiskLevel === 'Medium' ? 'bg-amber-500/10 text-amber-400' : 'bg-rose-500/10 text-rose-400'}`}>
                  {pollRiskLevel}
                </span>
              </h4>

              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-cyber-muted font-mono">Dynamic Risk Score:</span>
                  <span className={`text-sm font-bold font-mono ${pollRiskScore > 75 ? 'text-rose-500' : pollRiskScore > 40 ? 'text-amber-500' : 'text-emerald-400'}`}>
                    {pollRiskScore} / 100
                  </span>
                </div>
                
                <div className="w-full h-1.5 bg-cyber-panel rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${pollRiskScore > 75 ? 'bg-rose-500' : pollRiskScore > 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${pollRiskScore}%` }}
                  ></div>
                </div>

                {pollRiskDetails.length > 0 ? (
                  <div className="space-y-1.5 pt-2">
                    <p className="text-[9px] font-mono uppercase tracking-wider text-cyber-muted">Active Risk Indicators:</p>
                    <div className="space-y-1">
                      {pollRiskDetails.map((det, idx) => (
                        <div key={idx} className="bg-cyber-panel/50 border border-cyber-border rounded px-2 py-1 text-[9px] text-cyber-text font-mono flex items-start">
                          <AlertOctagon className="w-3 h-3 text-amber-500 mr-1 flex-shrink-0 mt-0.5" />
                          <span>{det}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-[10px] text-cyber-muted italic text-center pt-2">No security anomalies detected. Access parameters are within baseline tolerances.</p>
                )}
              </div>
            </div>

            {/* MFA management Card */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-primary border-b border-cyber-border pb-2 flex items-center">
                <Smartphone className="w-4 h-4 mr-1.5" /> Identity Protection
              </h4>

              {mfaEnabledUser ? (
                <div className="space-y-3">
                  <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded p-3 text-[11px] flex items-center">
                    <Check className="w-4 h-4 mr-1.5 flex-shrink-0" />
                    <span>MFA (TOTP) is active on this account</span>
                  </div>
                  {mfaBackupCodes.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">MFA Backup Codes</p>
                      <div className="bg-cyber-panel border border-cyber-border rounded p-2 text-[10px] font-mono text-cyber-text select-all whitespace-pre">
                        {mfaBackupCodes.join('\n')}
                      </div>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(mfaBackupCodes.join('\n'));
                          setCopiedCodes(true);
                          setTimeout(() => setCopiedCodes(false), 2000);
                        }}
                        className="w-full text-center bg-cyber-panel hover:bg-cyber-border text-cyber-muted hover:text-cyber-text py-1.5 rounded text-[10px] font-mono uppercase border border-cyber-border"
                      >
                        {copiedCodes ? 'Copied!' : 'Copy codes'}
                      </button>
                    </div>
                  )}
                </div>
              ) : mfaSetupActive ? (
                <div className="space-y-3 text-center">
                  <div className="bg-cyber-panel p-2.5 rounded border border-cyber-border inline-block">
                    <div className="w-32 h-32 bg-white flex items-center justify-center p-2 rounded">
                      <div className="w-full h-full border-2 border-black border-dashed flex flex-col items-center justify-center text-[10px] text-black text-center leading-tight">
                        <span className="font-bold">QR Enrollment</span>
                        <span className="font-mono text-[8px] bg-gray-100 p-0.5 mt-1 border break-all select-all font-semibold">
                          {mfaSecret}
                        </span>
                      </div>
                    </div>
                  </div>
                  <p className="text-[10px] text-cyber-muted text-left leading-relaxed">
                    Scan the QR code or enter this secret key inside Google Authenticator, then submit the code below:
                  </p>
                  <div className="space-y-2">
                    <input
                      type="text"
                      placeholder="Enter 6-digit code"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text text-center p-1.5 rounded font-mono text-xs focus:outline-none focus:border-cyber-primary"
                    />
                    <button
                      onClick={confirmMFASetup}
                      className="w-full bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono font-bold uppercase py-1.5 rounded text-[10px] tracking-wider transition-colors"
                    >
                      Confirm Configuration
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-[11px] text-cyber-muted leading-relaxed">
                    Protect your corporate user identity. Enrolling an MFA device reduces your baseline user risk score.
                  </p>
                  <button
                    onClick={startMFASetup}
                    className="w-full bg-cyber-primary/10 hover:bg-cyber-primary/20 border border-cyber-primary/30 text-cyber-primary font-mono font-bold py-2 rounded text-[10px] uppercase tracking-wider transition-all"
                  >
                    Configure MFA Device
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right column: Protected Resources */}
          <div className="md:col-span-2 space-y-6">
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-secondary border-b border-cyber-border pb-2 flex items-center">
                <Key className="w-4 h-4 mr-1.5" /> Corporate Intranet Resources
              </h4>
              
              <p className="text-[11px] text-cyber-muted">
                Select an internal corporate node to access. The ZTNA Gateway continuously validates your authorization, device health, and risk score.
              </p>

              <div className="grid grid-cols-3 gap-3">
                <button
                  onClick={() => accessResource('payroll')}
                  className={`p-3 rounded border font-mono text-center transition-all flex flex-col items-center justify-center space-y-2 ${activeResource === 'payroll' ? 'bg-cyber-secondary/15 border-cyber-secondary text-cyber-secondary shadow-cyber-glow-blue' : 'bg-cyber-panel border-cyber-border text-cyber-text hover:border-cyber-muted'}`}
                >
                  <Database className="w-5 h-5" />
                  <span className="text-[10px] font-bold uppercase tracking-wider">Payroll Db</span>
                </button>

                <button
                  onClick={() => accessResource('ssh')}
                  className={`p-3 rounded border font-mono text-center transition-all flex flex-col items-center justify-center space-y-2 ${activeResource === 'ssh' ? 'bg-cyber-secondary/15 border-cyber-secondary text-cyber-secondary shadow-cyber-glow-blue' : 'bg-cyber-panel border-cyber-border text-cyber-text hover:border-cyber-muted'}`}
                >
                  <Terminal className="w-5 h-5" />
                  <span className="text-[10px] font-bold uppercase tracking-wider">Secure SSH</span>
                </button>

                <button
                  onClick={() => accessResource('api')}
                  className={`p-3 rounded border font-mono text-center transition-all flex flex-col items-center justify-center space-y-2 ${activeResource === 'api' ? 'bg-cyber-secondary/15 border-cyber-secondary text-cyber-secondary shadow-cyber-glow-blue' : 'bg-cyber-panel border-cyber-border text-cyber-text hover:border-cyber-muted'}`}
                >
                  <Server className="w-5 h-5" />
                  <span className="text-[10px] font-bold uppercase tracking-wider">Config API</span>
                </button>
              </div>

              {/* Display resource viewport */}
              {activeResource && (
                <div className="border border-cyber-border rounded overflow-hidden mt-4">
                  <div className="bg-cyber-panel px-3 py-1.5 border-b border-cyber-border flex justify-between items-center text-[10px] font-mono">
                    <span className="text-cyber-muted uppercase font-bold">Node Connection Viewport: {activeResource}</span>
                    <button onClick={() => setActiveResource(null)} className="text-rose-400 hover:text-rose-300 font-bold uppercase">Close</button>
                  </div>

                  <div className="p-4 bg-cyber-bg min-h-[160px] text-xs">
                    {loadingResource ? (
                      <div className="flex flex-col items-center justify-center min-h-[130px] text-cyber-muted space-y-2">
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        <span className="font-mono text-[10px]">Verifying credentials at gateway...</span>
                      </div>
                    ) : resourceError ? (
                      <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 p-4 rounded space-y-2">
                        <h5 className="font-mono font-bold uppercase text-[11px] flex items-center text-rose-400">
                          <AlertOctagon className="w-4 h-4 mr-1.5 flex-shrink-0" /> ACCESS DENIED BY ZTNA POLICY
                        </h5>
                        <p className="text-[11px] leading-relaxed">
                          {resourceError}
                        </p>
                      </div>
                    ) : activeResource === 'ssh' ? (
                      <div className="bg-black text-emerald-400 p-3 rounded font-mono text-[11px] space-y-2 h-[220px] overflow-y-auto border border-emerald-500/10">
                        <div className="space-y-1">
                          {sshTerminalOutput.map((out, idx) => (
                            <div key={idx} className="whitespace-pre-wrap">{out}</div>
                          ))}
                        </div>
                        <form onSubmit={executeSshCommand} className="flex items-center pt-2 border-t border-emerald-500/10 mt-2">
                          <span className="mr-1.5 text-emerald-500">$</span>
                          <input
                            type="text"
                            value={sshCommand}
                            onChange={(e) => setSshCommand(e.target.value)}
                            className="flex-1 bg-transparent text-emerald-400 border-none outline-none focus:ring-0 p-0 text-[11px]"
                            placeholder="Type command here..."
                          />
                        </form>
                      </div>
                    ) : (
                      <div className="bg-cyber-panel p-3 rounded border border-cyber-border font-mono text-[11px] text-cyber-text overflow-x-auto max-h-[220px]">
                        <pre>{JSON.stringify(resourceContent, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: SECOPS ATTACK & JIT LAB */}
      {activeSubTab === 'lab' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fadeIn">
          
          {/* Column A: JIT Request and Geolocation Hop */}
          <div className="space-y-6">
            
            {/* JIT Request form card */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-secondary border-b border-cyber-border pb-2 flex items-center">
                <Send className="w-4 h-4 mr-1.5 text-cyber-secondary" /> Just-In-Time Access Sandbox
              </h4>
              <p className="text-[11px] text-cyber-muted">
                If an ABAC policy blocks your user role, submit a temporary JIT access ticket. Administrators in the SecOps console can review and approve it.
              </p>

              {jitStatusMsg && (
                <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 p-2.5 rounded text-[11px] flex items-center">
                  <ShieldCheck className="w-4 h-4 mr-1.5 flex-shrink-0" />
                  <span>{jitStatusMsg}</span>
                </div>
              )}

              <form onSubmit={submitJITRequest} className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono text-cyber-muted uppercase">Target Resource</label>
                    <select
                      value={jitResource}
                      onChange={(e) => setJitResource(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                    >
                      <option value="payroll">Payroll Database</option>
                      <option value="ssh">SSH Shell Server</option>
                      <option value="api">Config API</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono text-cyber-muted uppercase">Duration Limit</label>
                    <select
                      value={jitDuration}
                      onChange={(e) => setJitDuration(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none font-mono"
                    >
                      <option value="5">5 Minutes</option>
                      <option value="15">15 Minutes</option>
                      <option value="60">1 Hour</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono text-cyber-muted uppercase">Justification / Reason</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Performing database schema audit"
                    value={jitReason}
                    onChange={(e) => setJitReason(e.target.value)}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full bg-cyber-secondary hover:bg-blue-600 text-cyber-bg font-mono font-bold uppercase py-2 rounded transition-all text-[10px] tracking-wider shadow-cyber-glow-blue"
                >
                  Request JIT Authorization
                </button>
              </form>
            </div>

            {/* Geolocation Travel Anomaly card */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-danger border-b border-cyber-border pb-2 flex items-center">
                <Zap className="w-4 h-4 mr-1.5 text-cyber-danger" /> Impossible Travel Simulator
              </h4>
              <p className="text-[11px] text-cyber-muted">
                Zero Trust blocks access if a session changes locations faster than physically possible. Click below to warp your IP address/country to Russia.
              </p>

              <button
                onClick={() => {
                  updateSimulatedDevice({
                    country: 'RU',
                    isVPN: true,
                    hostname: 'ru-proxy-exit-node',
                    macHash: 'f4:e5:d6:c3:b2:a1'
                  });
                  addConsoleMessage('Impossible Travel Simulation: Geolocation warped to Moscow (RU)', 'warn');
                }}
                className="w-full bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 font-mono font-bold py-2 rounded text-[10px] uppercase tracking-wider transition-colors"
              >
                Simulate Travel Jump to Russia (RU)
              </button>
              <p className="text-[9.5px] text-cyber-muted italic text-center">
                (Observe: the next polling tick at the top-right will fail, lock your session, and logout!)
              </p>
            </div>

          </div>

          {/* Column B: WAF SQL Injection and Brute Force Flooder */}
          <div className="space-y-6">
            
            {/* WAF SQL Injection Sandbox */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-danger border-b border-cyber-border pb-2 flex items-center">
                <ShieldAlert className="w-4 h-4 mr-1.5 text-cyber-danger" /> WAF SQL Injection Laboratory
              </h4>
              <p className="text-[11px] text-cyber-muted leading-relaxed">
                The gateway intercepts incoming request queries. Attempt to bypass department filtering.
              </p>
              
              <div className="bg-cyber-panel p-2.5 rounded border border-cyber-border text-[10px] font-mono text-cyber-primary leading-normal">
                SQL Query:<br />
                <span className="text-cyber-text">SELECT * FROM payroll WHERE department = '</span>
                <span className="text-amber-400 font-semibold">{sqlDept || '[INPUT]'}</span>
                <span className="text-cyber-text">'</span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex space-x-1.5">
                  <input
                    type="text"
                    placeholder="e.g. Engineering"
                    value={sqlDept}
                    onChange={(e) => setSqlDept(e.target.value)}
                    className="flex-1 bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none font-mono text-xs"
                  />
                  <button
                    onClick={() => setSqlDept("' OR '1'='1")}
                    className="bg-cyber-panel hover:bg-cyber-border border border-cyber-border text-cyber-text px-2 py-1 rounded font-mono text-[9px] uppercase"
                  >
                    Payload
                  </button>
                </div>

                <button
                  onClick={runSQLiExploit}
                  disabled={sqliLoading}
                  className="w-full bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono font-bold uppercase py-2 rounded text-[10px] tracking-wider transition-colors shadow-cyber-glow"
                >
                  {sqliLoading ? 'Sending payload...' : 'Send Query to Gateway'}
                </button>

                {/* Exploit outputs */}
                {sqliError && (
                  <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 p-2.5 rounded text-[11px] flex items-start space-x-1.5 font-mono">
                    <AlertOctagon className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-500" />
                    <div>
                      <span className="font-bold">WAF BLOCKED:</span> {sqliError}
                    </div>
                  </div>
                )}

                {sqliResult && (
                  <div className="bg-cyber-panel border border-emerald-500/20 rounded p-2 text-[10px] font-mono text-emerald-400 max-h-[120px] overflow-y-auto">
                    <p className="font-bold mb-1">🔥 EXPLOIT SUCCESS (Bypassed filter!):</p>
                    <pre className="text-cyber-text">{JSON.stringify(sqliResult, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>

            {/* Brute Force Flooder simulator card */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
              <h4 className="font-mono text-xs uppercase tracking-wider text-cyber-danger border-b border-cyber-border pb-2 flex items-center">
                <ShieldAlert className="w-4 h-4 mr-1.5 text-cyber-danger" /> Identity Brute Force Simulator
              </h4>
              <p className="text-[11px] text-cyber-muted leading-relaxed">
                Send rapid authentication requests with incorrect passwords to trigger the account lockout threshold.
              </p>

              <button
                onClick={runBruteForceFlood}
                disabled={bruteForceLoading}
                className="w-full bg-cyber-panel hover:bg-rose-950/20 border border-cyber-border hover:border-rose-500/30 text-cyber-text hover:text-rose-400 font-mono font-bold py-2 rounded text-[10px] uppercase tracking-wider transition-colors"
              >
                {bruteForceLoading ? 'Flooding auth server...' : 'Simulate login flood attack'}
              </button>

              {bruteForceLogs.length > 0 && (
                <div className="bg-black text-rose-400 p-2.5 rounded border border-rose-500/10 h-28 overflow-y-auto font-mono text-[9px] space-y-1">
                  {bruteForceLogs.map((log, idx) => (
                    <div key={idx}>{log}</div>
                  ))}
                </div>
              )}
            </div>

          </div>

        </div>
      )}

    </div>
  );
};
