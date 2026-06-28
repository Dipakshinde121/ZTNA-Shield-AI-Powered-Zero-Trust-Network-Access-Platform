import React, { useState, useEffect, useRef } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { ztnaFetch } from '../utils/api';
import { Users, Monitor, ShieldAlert, RefreshCw, Check, X, Search, Settings } from 'lucide-react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { Line, Bar } from 'react-chartjs-2';

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip, Legend, Filler);

// HTML5 Canvas interactive threat map node positions
interface MapNode {
  id: string;
  label: string;
  x: number;
  y: number;
  type: 'client' | 'attacker' | 'gateway' | 'app' | 'db';
  status: 'online' | 'blocked' | 'attacked';
}

interface Particle {
  id: string;
  startX: number;
  startY: number;
  endX: number;
  endY: number;
  x: number;
  y: number;
  progress: number;
  speed: number;
  color: string;
  size: number;
  blocked: boolean;
}

export const SOCDashboard: React.FC = () => {
  const { token, simulatedDevice, addConsoleMessage } = useSimulation();

  const [activeTab, setActiveTab] = useState<'metrics' | 'map' | 'sessions' | 'policies' | 'devices' | 'jit' | 'logs' | 'compliance'>('metrics');
  
  // Metrics states
  const [metrics, setMetrics] = useState({
    totalUsers: 0,
    activeSessionsCount: 0,
    totalDevicesCount: 0,
    compromisedDevicesCount: 0,
    blockedDevicesCount: 0,
    threatsBlockedCount: 0,
    averageRiskScore: 0
  });

  // Table states
  const [sessions, setSessions] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [jitRequests, setJitRequests] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);

  // Filtering states
  const [searchLogQuery, setSearchLogQuery] = useState('');
  const [logFilterCategory, setLogFilterCategory] = useState('');
  const [logFilterLevel, setLogFilterLevel] = useState('');

  // Loading / refreshing indicators
  const [loading, setLoading] = useState(false);

  // New Policy form state
  const [showPolicyForm, setShowPolicyForm] = useState(false);
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyDesc, setNewPolicyDesc] = useState('');
  const [newPolicyType, setNewPolicyType] = useState<'RBAC' | 'ABAC'>('ABAC');
  const [newPolicyRoles, setNewPolicyRoles] = useState<string[]>([]);
  const [newPolicyMinTrust, setNewPolicyMinTrust] = useState<string>('');
  const [newPolicyMaxRisk, setNewPolicyMaxRisk] = useState<number>(45);

  // Canvas ref for Threat Map
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationFrameRef = useRef<number | null>(null);
  const particlesRef = useRef<Particle[]>([]);

  // Fetch all administrative datasets
  const refreshAllData = async () => {
    if (!token) return;
    setLoading(true);

    try {
      // Metrics
      const resMetrics = await ztnaFetch('/api/admin/metrics', 'GET', simulatedDevice, token);
      if (resMetrics.ok) setMetrics(await resMetrics.json());

      // Sessions
      const resSessions = await ztnaFetch('/api/admin/sessions', 'GET', simulatedDevice, token);
      if (resSessions.ok) setSessions(await resSessions.json());

      // Devices
      const resDevices = await ztnaFetch('/api/devices', 'GET', simulatedDevice, token);
      if (resDevices.ok) setDevices(await resDevices.json());

      // Policies
      const resPolicies = await ztnaFetch('/api/admin/policies', 'GET', simulatedDevice, token);
      if (resPolicies.ok) setPolicies(await resPolicies.json());

      // JIT requests
      const resJit = await ztnaFetch('/api/admin/jit-requests', 'GET', simulatedDevice, token);
      if (resJit.ok) setJitRequests(await resJit.json());

      // Logs
      const queryParams = `?q=${searchLogQuery}&category=${logFilterCategory}&level=${logFilterLevel}`;
      const resLogs = await ztnaFetch(`/api/admin/logs${queryParams}`, 'GET', simulatedDevice, token);
      if (resLogs.ok) setLogs(await resLogs.json());

    } catch (e) {
      console.error('Failed to fetch SOC telemetry details:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshAllData();
  }, [token, activeTab]);

  // Handle Session Revocation
  const revokeSession = async (sessionId: string) => {
    if (!token) return;
    if (!confirm('Are you sure you want to revoke this session? The user will be disconnected immediately.')) return;

    try {
      const response = await ztnaFetch(`/api/admin/sessions/${sessionId}/revoke`, 'POST', simulatedDevice, token);
      if (response.ok) {
        addConsoleMessage(`Session ${sessionId} manually terminated by administrator.`, 'success');
        refreshAllData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Handle JIT Approvals
  const processJIT = async (requestId: string, action: 'approve' | 'reject') => {
    if (!token) return;
    try {
      const response = await ztnaFetch(`/api/admin/jit-requests/${requestId}/${action}`, 'PUT', simulatedDevice, token);
      if (response.ok) {
        addConsoleMessage(`JIT access request ${requestId} resolved: ${action.toUpperCase()}`, 'success');
        refreshAllData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Toggle Policy Active State
  const togglePolicy = async (id: string, currentActiveState: boolean) => {
    if (!token) return;
    try {
      const response = await ztnaFetch(`/api/admin/policies/${id}`, 'PUT', simulatedDevice, token, {
        active: !currentActiveState
      });
      if (response.ok) {
        addConsoleMessage(`Policy status modified: ${id}`, 'success');
        refreshAllData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Create Policy
  const createPolicySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;

    const payload = {
      name: newPolicyName,
      description: newPolicyDesc,
      type: newPolicyType,
      rules: {
        roles: newPolicyType === 'RBAC' ? newPolicyRoles : undefined,
        minTrustLevel: newPolicyType === 'ABAC' && newPolicyMinTrust ? newPolicyMinTrust : undefined,
        maxRiskScore: newPolicyType === 'ABAC' ? newPolicyMaxRisk : undefined
      }
    };

    try {
      const response = await ztnaFetch('/api/admin/policies', 'POST', simulatedDevice, token, payload);
      if (response.ok) {
        addConsoleMessage(`Security Policy created: ${newPolicyName}`, 'success');
        setShowPolicyForm(false);
        setNewPolicyName('');
        setNewPolicyDesc('');
        setNewPolicyRoles([]);
        setNewPolicyMinTrust('');
        refreshAllData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Update Device posture manually (Trust, block, compromise)
  const setDevicePostureStatus = async (deviceId: string, status: string) => {
    if (!token) return;
    try {
      const response = await ztnaFetch(`/api/devices/${deviceId}/status`, 'PUT', simulatedDevice, token, { status });
      if (response.ok) {
        addConsoleMessage(`Posture status for device ${deviceId} changed to ${status}`, 'success');
        refreshAllData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Start threat map canvas animations on map view active
  useEffect(() => {
    if (activeTab !== 'map') {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = 750;
    canvas.height = 360;

    // Define fixed nodes
    const nodes: MapNode[] = [
      { id: 'usr-1', label: 'User Workstation (Normal)', x: 100, y: 80, type: 'client', status: 'online' },
      { id: 'atk-1', label: 'Botnet Attacker (Simulated)', x: 100, y: 280, type: 'attacker', status: 'attacked' },
      { id: 'gate', label: 'ZTNA Secure Gateway', x: 380, y: 180, type: 'gateway', status: 'online' },
      { id: 'srv-1', label: 'Internal Payroll (Web)', x: 650, y: 80, type: 'app', status: 'online' },
      { id: 'db-1', label: 'Production Database (SSH)', x: 650, y: 280, type: 'db', status: 'online' }
    ];

    // Animation Loop
    const drawMap = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw background network Grid lines
      ctx.strokeStyle = 'rgba(34, 40, 52, 0.2)';
      ctx.lineWidth = 1;
      const gridSize = 30;
      for (let x = 0; x < canvas.width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      // Draw connection vectors between nodes
      ctx.strokeStyle = 'rgba(34, 40, 52, 0.6)';
      ctx.lineWidth = 1.5;
      
      // Draw vectors Client -> Gateway, Attacker -> Gateway
      ctx.beginPath();
      ctx.moveTo(100, 80); ctx.lineTo(380, 180);
      ctx.moveTo(100, 280); ctx.lineTo(380, 180);
      
      // Draw vectors Gateway -> App, Gateway -> DB
      ctx.moveTo(380, 180); ctx.lineTo(650, 80);
      ctx.moveTo(380, 180); ctx.lineTo(650, 280);
      ctx.stroke();

      // Spawn random particles representing normal traffic and block flows
      if (Math.random() < 0.08) {
        // Normal Traffic
        particlesRef.current.push({
          id: `p-${Math.random()}`,
          startX: 100, startY: 80,
          endX: 380, endY: 180,
          x: 100, y: 80,
          progress: 0,
          speed: 0.01 + Math.random() * 0.01,
          color: '#10b981', // green
          size: 3,
          blocked: false
        });
      }

      // Update and Draw Particles
      particlesRef.current.forEach((p, idx) => {
        p.progress += p.speed;

        // Linear interpolation
        p.x = p.startX + (p.endX - p.startX) * p.progress;
        p.y = p.startY + (p.endY - p.startY) * p.progress;

        // Draw particle
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.shadowBlur = 10;
        ctx.shadowColor = p.color;
        ctx.fill();
        ctx.shadowBlur = 0; // reset

        // When particle reaches Gateway
        if (p.progress >= 0.98) {
          if (p.startX === 100 && p.startY === 280) {
            // Simulated Attack particle reaches Gateway -> EXPLODE/BLOCK
            // Trigger spark explosion
            ctx.beginPath();
            ctx.arc(p.endX, p.endY, 12, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.3)';
            ctx.fill();
            
            p.blocked = true;
          } else if (!p.blocked && p.endX === 380 && p.endY === 180) {
            // Normal particle reaches Gateway -> route to final destination
            const targets = [
              { x: 650, y: 80 }, // App
              { x: 650, y: 280 }  // Db
            ];
            const target = targets[Math.floor(Math.random() * targets.length)];
            
            // Spawn next hop particle
            particlesRef.current.push({
              id: `p-hop-${Math.random()}`,
              startX: 380, startY: 180,
              endX: target.x, endY: target.y,
              x: 380, y: 180,
              progress: 0,
              speed: 0.015,
              color: '#10b981',
              size: 3,
              blocked: false
            });
          }
          // Remove completed particle
          particlesRef.current.splice(idx, 1);
        }
      });

      // Draw Nodes
      nodes.forEach(node => {
        // Outer glow rings
        ctx.beginPath();
        ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);
        
        let color = '#10b981'; // green
        if (node.type === 'attacker' || node.status === 'attacked') color = '#ef4444'; // red
        if (node.type === 'gateway') color = '#3b82f6'; // blue
        
        ctx.fillStyle = `${color}15`;
        ctx.strokeStyle = `${color}40`;
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();

        // Inner solid core
        ctx.beginPath();
        ctx.arc(node.x, node.y, 10, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.shadowBlur = 15;
        ctx.shadowColor = color;
        ctx.fill();
        ctx.shadowBlur = 0; // reset

        // Labels
        ctx.fillStyle = '#f3f4f6';
        ctx.font = "bold 9px 'JetBrains Mono', monospace";
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y - 28);
      });

      animationFrameRef.current = requestAnimationFrame(drawMap);
    };

    drawMap();

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [activeTab]);

  // Trigger Simulated Attack
  const triggerVisualAttackSimulation = (type: 'ddos' | 'sqli') => {
    addConsoleMessage(`[ATTACK SIMULATION] Starting visual ${type.toUpperCase()} attack flow...`, 'warn');
    
    // Spawn heavy streams of red packets from attacker node on canvas
    for (let i = 0; i < 60; i++) {
      setTimeout(() => {
        particlesRef.current.push({
          id: `p-atk-${Date.now()}-${i}`,
          startX: 100, startY: 280,
          endX: 380, endY: 180,
          x: 100, y: 280,
          progress: 0,
          speed: 0.01 + Math.random() * 0.02,
          color: '#ef4444', // red
          size: 3.5,
          blocked: false
        });
      }, i * 60);
    }
  };

  // Mock charting data for metrics dashboard
  const lineChartData = {
    labels: ['18:00', '19:00', '20:00', '21:00', '22:00', '23:00'],
    datasets: [
      {
        label: 'Threat Requests Intercepted',
        data: [12, 19, 3, 5, 2, 24],
        fill: true,
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderColor: '#ef4444',
        borderWidth: 1.5,
        tension: 0.4
      },
      {
        label: 'Normal Requests Authenticated',
        data: [142, 192, 108, 120, 115, 175],
        fill: true,
        backgroundColor: 'rgba(16, 185, 129, 0.05)',
        borderColor: '#10b981',
        borderWidth: 1.5,
        tension: 0.4
      }
    ]
  };

  const barChartData = {
    labels: ['US', 'GB', 'IN', 'DE', 'RU', 'CN'],
    datasets: [
      {
        label: 'Active Users by Location',
        data: [15, 6, 8, 4, 1, 0],
        backgroundColor: '#3b82f6',
        borderColor: 'rgba(59, 130, 246, 0.5)',
        borderWidth: 1
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 9 } }
      }
    },
    scales: {
      x: { grid: { color: 'rgba(34, 40, 52, 0.15)' }, ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 8 } } },
      y: { grid: { color: 'rgba(34, 40, 52, 0.15)' }, ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 8 } } }
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-4 space-y-6">
      
      {/* Tab controls */}
      <div className="flex border-b border-cyber-border font-mono text-xs uppercase tracking-wider space-x-1">
        <button
          onClick={() => setActiveTab('metrics')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'metrics' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          SOC Overview
        </button>
        <button
          onClick={() => setActiveTab('map')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'map' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Threat map
        </button>
        <button
          onClick={() => setActiveTab('sessions')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'sessions' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Sessions ({sessions.length})
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'policies' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Policies ({policies.length})
        </button>
        <button
          onClick={() => setActiveTab('devices')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'devices' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Devices ({devices.length})
        </button>
        <button
          onClick={() => setActiveTab('jit')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'jit' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          JIT ({jitRequests.filter(r => r.status === 'pending').length})
        </button>
        <button
          onClick={() => setActiveTab('logs')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'logs' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          SIEM Logs
        </button>
        <button
          onClick={() => setActiveTab('compliance')}
          className={`py-2 px-4 border border-cyber-border border-b-0 rounded-t transition-all ${activeTab === 'compliance' ? 'bg-cyber-card text-cyber-primary font-bold border-t-2 border-t-cyber-primary' : 'bg-cyber-panel text-cyber-muted hover:text-cyber-text'}`}
        >
          Compliance
        </button>
        <div className="flex-1 flex justify-end pb-1.5">
          <button 
            onClick={refreshAllData}
            disabled={loading}
            className="text-cyber-muted hover:text-cyber-primary border border-cyber-border rounded px-2 py-1 bg-cyber-panel flex items-center space-x-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* METRICS OVERVIEW PANEL */}
      {activeTab === 'metrics' && (
        <div className="space-y-6">
          {/* Neon Metrics Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Metric 1 */}
            <div className="bg-cyber-card border border-cyber-border rounded p-4 relative overflow-hidden shadow-cyber-glow">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono text-cyber-muted uppercase tracking-wider">Active User Sessions</span>
                <Users className="w-4 h-4 text-cyber-secondary" />
              </div>
              <p className="text-2xl font-bold font-mono text-cyber-text mt-2">{metrics.activeSessionsCount}</p>
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyber-secondary"></div>
            </div>

            {/* Metric 2 */}
            <div className="bg-cyber-card border border-cyber-border rounded p-4 relative overflow-hidden shadow-cyber-glow">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono text-cyber-muted uppercase tracking-wider">Devices Ingested</span>
                <Monitor className="w-4 h-4 text-cyber-primary" />
              </div>
              <p className="text-2xl font-bold font-mono text-cyber-text mt-2">{metrics.totalDevicesCount}</p>
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyber-primary"></div>
            </div>

            {/* Metric 3 */}
            <div className="bg-cyber-card border border-cyber-border rounded p-4 relative overflow-hidden shadow-cyber-glow">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono text-cyber-muted uppercase tracking-wider">Threats Intercepted</span>
                <ShieldAlert className="w-4 h-4 text-cyber-danger" />
              </div>
              <p className="text-2xl font-bold font-mono text-cyber-danger mt-2">{metrics.threatsBlockedCount}</p>
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyber-danger"></div>
            </div>

            {/* Metric 4 */}
            <div className="bg-cyber-card border border-cyber-border rounded p-4 relative overflow-hidden shadow-cyber-glow">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono text-cyber-muted uppercase tracking-wider">Average Anomaly Risk</span>
                <Settings className="w-4 h-4 text-cyber-warning" />
              </div>
              <p className={`text-2xl font-bold font-mono mt-2 ${metrics.averageRiskScore > 40 ? 'text-cyber-danger' : 'text-cyber-primary'}`}>{metrics.averageRiskScore} / 100</p>
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyber-warning"></div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-lg p-4 h-[260px] relative">
              <h4 className="font-mono text-xs font-bold text-cyber-text mb-3 uppercase tracking-wider">Access Requests vs Threat Interceptions</h4>
              <div className="h-[200px]">
                <Line data={lineChartData} options={chartOptions} />
              </div>
            </div>
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 h-[260px] relative">
              <h4 className="font-mono text-xs font-bold text-cyber-text mb-3 uppercase tracking-wider">Sessions by Country</h4>
              <div className="h-[200px]">
                <Bar data={barChartData} options={chartOptions} />
              </div>
            </div>
          </div>

          {/* Critical threat logs overview */}
          <div className="bg-cyber-card border border-cyber-border rounded-lg p-4">
            <h4 className="font-mono text-xs font-bold text-cyber-text mb-3 uppercase tracking-wider flex items-center">
              <ShieldAlert className="w-4 h-4 text-cyber-danger mr-1.5" /> High Risk Security Violations
            </h4>
            <div className="space-y-2 max-h-[160px] overflow-y-auto">
              {logs.filter(l => l.level === 'critical' || l.level === 'error').length === 0 ? (
                <p className="text-xs text-cyber-muted italic text-center py-4">No critical security events recorded.</p>
              ) : (
                logs.filter(l => l.level === 'critical' || l.level === 'error').map(l => (
                  <div key={l.id} className="bg-rose-500/5 border border-rose-500/20 rounded p-2.5 flex items-start justify-between text-xs font-mono">
                    <div className="space-y-1">
                      <span className="text-rose-500 font-bold">[{l.level.toUpperCase()}][{l.category.toUpperCase()}]</span>
                      <p className="text-cyber-text">{l.message}</p>
                      <p className="text-[10px] text-cyber-muted">{l.details}</p>
                    </div>
                    <span className="text-[10px] text-cyber-muted flex-shrink-0">{new Date(l.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* THREAT MAP PANEL */}
      {activeTab === 'map' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">ZTNA Firewall & Routing Sandbox</h3>
              <p className="text-[11px] text-cyber-muted">
                Visualizing data flow routing. Blue represents the ZTNA reverse proxy validating authentication state on every message.
              </p>
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => triggerVisualAttackSimulation('ddos')}
                className="bg-rose-500/10 hover:bg-rose-500/25 border border-rose-500/30 text-rose-400 font-mono text-[10px] uppercase font-bold py-1.5 px-3 rounded transition-colors"
              >
                Simulate DDoS Flood
              </button>
              <button
                onClick={() => triggerVisualAttackSimulation('sqli')}
                className="bg-amber-500/10 hover:bg-amber-500/25 border border-amber-500/30 text-amber-400 font-mono text-[10px] uppercase font-bold py-1.5 px-3 rounded transition-colors"
              >
                Simulate SQLi Intrusion
              </button>
            </div>
          </div>

          <div className="bg-[#040508] border border-cyber-border rounded overflow-hidden flex items-center justify-center">
            <canvas ref={canvasRef} className="block w-full max-w-[750px]" />
          </div>
        </div>
      )}

      {/* ACTIVE SESSIONS PANEL */}
      {activeTab === 'sessions' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">Authenticated User Sessions</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs border-collapse">
              <thead>
                <tr className="border-b border-cyber-border text-cyber-muted font-mono text-[10px] uppercase tracking-wider">
                  <th className="py-2.5">User Identity</th>
                  <th>IP / Location</th>
                  <th>Device Hostname</th>
                  <th>Risk Score</th>
                  <th>Active Status</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-6 text-cyber-muted italic">No sessions registered in security cluster.</td>
                  </tr>
                ) : (
                  sessions.map(s => (
                    <tr key={s.id} className="border-b border-cyber-border/40 hover:bg-cyber-panel/30">
                      <td className="py-3">
                        <div className="font-semibold text-cyber-text">{s.userEmail}</div>
                        <div className="text-[10px] text-cyber-primary font-mono uppercase font-bold">{s.userRole}</div>
                      </td>
                      <td>
                        <div className="font-mono">{s.location.ip}</div>
                        <div className="text-[10px] text-cyber-muted">{s.location.country} ({s.location.vpn ? 'VPN' : 'Direct'})</div>
                      </td>
                      <td className="font-mono text-[11px] text-cyber-text">
                        {s.deviceHostname}
                        <div className="text-[9px] text-cyber-muted uppercase">{s.deviceOS}</div>
                      </td>
                      <td className="font-mono">
                        <span className={`font-bold ${s.riskScore > 60 ? 'text-rose-500' : s.riskScore > 30 ? 'text-amber-500' : 'text-emerald-400'}`}>
                          {s.riskScore}
                        </span>
                      </td>
                      <td>
                        {s.active ? (
                          <span className="bg-emerald-500/10 text-emerald-400 text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/20 font-bold">ACTIVE</span>
                        ) : (
                          <span className="bg-cyber-border text-cyber-muted text-[10px] font-mono px-1.5 py-0.5 rounded border border-cyber-border/60">REVOKED</span>
                        )}
                      </td>
                      <td className="text-right">
                        {s.active && (
                          <button
                            onClick={() => revokeSession(s.id)}
                            className="text-rose-400 hover:text-rose-300 font-mono text-[10px] uppercase font-bold border border-rose-500/20 bg-rose-500/5 hover:bg-rose-500/10 py-1 px-2.5 rounded transition-all"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* POLICY EDITOR PANEL */}
      {activeTab === 'policies' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">Access Enforcement Policies</h3>
            <button
              onClick={() => setShowPolicyForm(!showPolicyForm)}
              className="bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono text-[10px] uppercase font-bold py-1.5 px-3 rounded flex items-center transition-all shadow-cyber-glow"
            >
              {showPolicyForm ? 'Cancel' : 'Create Policy'}
            </button>
          </div>

          {/* New Policy Form */}
          {showPolicyForm && (
            <form onSubmit={createPolicySubmit} className="bg-cyber-panel border border-cyber-border rounded p-4 space-y-4 text-xs">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono uppercase text-cyber-muted">Policy Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Enforce Disk Encryption"
                    value={newPolicyName}
                    onChange={(e) => setNewPolicyName(e.target.value)}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono uppercase text-cyber-muted">Policy Model Type</label>
                  <select
                    value={newPolicyType}
                    onChange={(e: any) => setNewPolicyType(e.target.value)}
                    className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                  >
                    <option value="ABAC">ABAC (Attribute-Based)</option>
                    <option value="RBAC">RBAC (Role-Based)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase text-cyber-muted">Description</label>
                <input
                  type="text"
                  required
                  placeholder="Explain what access rules this policy applies"
                  value={newPolicyDesc}
                  onChange={(e) => setNewPolicyDesc(e.target.value)}
                  className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                />
              </div>

              {/* Dynamic rule fields depending on type selection */}
              {newPolicyType === 'RBAC' ? (
                <div className="space-y-2">
                  <label className="block text-[10px] font-mono uppercase text-cyber-muted">Restrict access to these roles</label>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {['Super Admin', 'Security Administrator', 'IT Administrator', 'Manager', 'Employee'].map(r => (
                      <label key={r} className="flex items-center space-x-1 bg-cyber-bg border border-cyber-border rounded px-2.5 py-1 cursor-pointer hover:border-cyber-primary select-none">
                        <input
                          type="checkbox"
                          checked={newPolicyRoles.includes(r)}
                          onChange={() => {
                            if (newPolicyRoles.includes(r)) {
                              setNewPolicyRoles(newPolicyRoles.filter(role => role !== r));
                            } else {
                              setNewPolicyRoles([...newPolicyRoles, r]);
                            }
                          }}
                          className="rounded text-cyber-primary focus:ring-0"
                        />
                        <span className="font-mono text-[9px] text-cyber-text">{r}</span>
                      </label>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase text-cyber-muted">Minimum Device State Required</label>
                    <select
                      value={newPolicyMinTrust}
                      onChange={(e) => setNewPolicyMinTrust(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-2 rounded focus:outline-none"
                    >
                      <option value="">No device checks</option>
                      <option value="Trusted">Trusted Device State</option>
                      <option value="Unknown">Unknown Posture or above</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <label className="block text-[10px] font-mono uppercase text-cyber-muted">Maximum Allowed Risk Score</label>
                      <span className="font-mono font-bold text-cyber-primary">{newPolicyMaxRisk}</span>
                    </div>
                    <input
                      type="range"
                      min="10"
                      max="90"
                      value={newPolicyMaxRisk}
                      onChange={(e) => setNewPolicyMaxRisk(parseInt(e.target.value))}
                      className="w-full h-1.5 bg-cyber-border rounded-lg appearance-none cursor-pointer focus:outline-none bg-cyber-bg mt-3"
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="w-full bg-cyber-primary hover:bg-emerald-600 text-cyber-bg font-mono font-bold uppercase py-2 rounded shadow-cyber-glow"
              >
                Deploy Policy to Gateway
              </button>
            </form>
          )}

          {/* Policy List */}
          <div className="space-y-3">
            {policies.map(p => (
              <div key={p.id} className="bg-cyber-panel border border-cyber-border rounded p-4 flex flex-col md:flex-row md:items-center justify-between space-y-3 md:space-y-0">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <h4 className="font-mono text-xs font-bold text-cyber-text">{p.name}</h4>
                    <span className="bg-cyber-bg border border-cyber-border text-cyber-muted text-[8px] font-mono px-1 rounded-sm uppercase">{p.type}</span>
                  </div>
                  <p className="text-[11px] text-cyber-muted">{p.description}</p>
                  
                  {/* Print policy settings summary */}
                  <div className="pt-2 font-mono text-[9px] text-cyber-primary flex flex-wrap gap-2">
                    {p.rules.roles && <span>[Roles: {p.rules.roles.join(', ')}]</span>}
                    {p.rules.minTrustLevel && <span>[Min Trust: {p.rules.minTrustLevel}]</span>}
                    {p.rules.maxRiskScore !== undefined && <span>[Max Risk Score: {p.rules.maxRiskScore}]</span>}
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  {/* Status Toggle Switch */}
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono text-cyber-muted uppercase">Status:</span>
                    <button
                      onClick={() => togglePolicy(p.id, p.active)}
                      className={`font-mono text-[9px] uppercase font-bold py-1 px-2.5 rounded border transition-all ${p.active ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-cyber-bg border-cyber-border text-cyber-muted'}`}
                    >
                      {p.active ? 'Enforcing' : 'Deactivated'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DEVICE INVENTORY PANEL */}
      {activeTab === 'devices' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">Registered Device Inventory</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-sans text-xs border-collapse">
              <thead>
                <tr className="border-b border-cyber-border text-cyber-muted font-mono text-[10px] uppercase tracking-wider">
                  <th className="py-2.5">Hostname / Fingerprint</th>
                  <th>Operating System</th>
                  <th>Security Posture</th>
                  <th>Posture State</th>
                  <th className="text-right">Administrative overrides</th>
                </tr>
              </thead>
              <tbody>
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-6 text-cyber-muted italic">No devices registered in posture directory.</td>
                  </tr>
                ) : (
                  devices.map(d => (
                    <tr key={d.id} className="border-b border-cyber-border/40 hover:bg-cyber-panel/30">
                      <td className="py-3">
                        <div className="font-semibold text-cyber-text">{d.hostname}</div>
                        <div className="text-[10px] text-cyber-muted font-mono select-all">FP: {d.fingerprint}</div>
                        <div className="text-[9px] text-cyber-primary font-mono">{d.userEmail} ({d.userRole})</div>
                      </td>
                      <td className="font-mono text-[11px]">{d.os}</td>
                      <td>
                        <div className="space-y-0.5 text-[9px] font-mono">
                          <div className={d.antivirus ? 'text-emerald-400' : 'text-rose-400'}>• Antivirus: {d.antivirus ? 'ON' : 'OFF'}</div>
                          <div className={d.firewall ? 'text-emerald-400' : 'text-rose-400'}>• Firewall: {d.firewall ? 'ON' : 'OFF'}</div>
                          <div className={d.diskEncryption ? 'text-emerald-400' : 'text-rose-400'}>• Encryption: {d.diskEncryption ? 'ON' : 'OFF'}</div>
                        </div>
                      </td>
                      <td>
                        {d.status === 'Trusted' && <span className="bg-emerald-500/10 text-emerald-400 text-[9px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/20 font-bold uppercase">TRUSTED</span>}
                        {d.status === 'Unknown' && <span className="bg-amber-500/10 text-amber-400 text-[9px] font-mono px-1.5 py-0.5 rounded border border-amber-500/20 font-bold uppercase">UNKNOWN</span>}
                        {d.status === 'Compromised' && <span className="bg-rose-500/10 text-rose-400 text-[9px] font-mono px-1.5 py-0.5 rounded border border-rose-500/20 font-bold uppercase">COMPROMISED</span>}
                        {d.status === 'Blocked' && <span className="bg-red-500/20 text-red-500 text-[9px] font-mono px-1.5 py-0.5 rounded border border-red-500/30 font-bold uppercase">BLOCKED</span>}
                      </td>
                      <td className="text-right space-x-1.5">
                        <select
                          value={d.status}
                          onChange={(e) => setDevicePostureStatus(d.id, e.target.value)}
                          className="bg-cyber-bg border border-cyber-border text-cyber-text p-1 rounded font-mono text-[10px]"
                        >
                          <option value="Trusted">Trust</option>
                          <option value="Unknown">Reset</option>
                          <option value="Compromised">Compromise</option>
                          <option value="Blocked">Block</option>
                        </select>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* JUST-IN-TIME (JIT) ACCESS PANEL */}
      {activeTab === 'jit' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">Just-In-Time Access Workflow</h3>
          <div className="space-y-3">
            {jitRequests.filter(r => r.status === 'pending').length === 0 ? (
              <p className="text-xs text-cyber-muted italic text-center py-6">No pending JIT requests awaiting administrator authorization.</p>
            ) : (
              jitRequests.filter(r => r.status === 'pending').map(r => (
                <div key={r.id} className="bg-cyber-panel border border-cyber-border rounded p-4 flex flex-col md:flex-row md:items-center justify-between space-y-3 md:space-y-0 text-xs">
                  <div className="space-y-1">
                    <div className="font-semibold text-cyber-text">{r.userEmail}</div>
                    <p className="text-cyber-muted leading-relaxed">
                      Requests temporary access to resource: <span className="text-cyber-primary font-mono font-bold uppercase">{r.resource}</span> for <span className="text-cyber-secondary font-mono font-bold">{r.durationMinutes} mins</span>.
                    </p>
                    <p className="italic text-[11px] bg-cyber-bg px-2 py-1 rounded border border-cyber-border inline-block mt-1">
                      Reason: "{r.reason}"
                    </p>
                  </div>

                  <div className="flex space-x-2">
                    <button
                      onClick={() => processJIT(r.id, 'approve')}
                      className="bg-emerald-500/10 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] uppercase font-bold py-1.5 px-3 rounded flex items-center space-x-1"
                    >
                      <Check className="w-3.5 h-3.5" /> <span>Approve</span>
                    </button>
                    <button
                      onClick={() => processJIT(r.id, 'reject')}
                      className="bg-rose-500/10 hover:bg-rose-500/25 border border-rose-500/30 text-rose-400 font-mono text-[10px] uppercase font-bold py-1.5 px-3 rounded flex items-center space-x-1"
                    >
                      <X className="w-3.5 h-3.5" /> <span>Reject</span>
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* SIEM LOG EXPLORER PANEL */}
      {activeTab === 'logs' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-4">
            <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">SIEM Centralized Security Logs</h3>
            
            {/* Live Search and filters */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <div className="relative">
                <Search className="absolute left-2.5 top-2 w-3.5 h-3.5 text-cyber-muted" />
                <input
                  type="text"
                  placeholder="Search logs..."
                  value={searchLogQuery}
                  onChange={(e) => setSearchLogQuery(e.target.value)}
                  className="bg-cyber-bg border border-cyber-border text-cyber-text pl-8 pr-3 py-1 rounded focus:outline-none"
                />
              </div>

              <select
                value={logFilterCategory}
                onChange={(e) => setLogFilterCategory(e.target.value)}
                className="bg-cyber-bg border border-cyber-border text-cyber-text px-2 py-1 rounded"
              >
                <option value="">All Categories</option>
                <option value="auth">Auth</option>
                <option value="device">Device</option>
                <option value="gateway">Gateway</option>
                <option value="threat">Threat</option>
                <option value="compliance">Compliance</option>
              </select>

              <select
                value={logFilterLevel}
                onChange={(e) => setLogFilterLevel(e.target.value)}
                className="bg-cyber-bg border border-cyber-border text-cyber-text px-2 py-1 rounded"
              >
                <option value="">All Priorities</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          {/* Logs Viewport */}
          <div className="bg-[#040508] border border-cyber-border rounded p-3 font-mono text-[10.5px] max-h-[360px] overflow-y-auto space-y-1.5">
            {logs.length === 0 ? (
              <p className="text-cyber-muted italic text-center py-6">No matching logs found.</p>
            ) : (
              logs.map(l => (
                <div key={l.id} className="border-b border-cyber-border/25 pb-1 select-text">
                  <div className="flex justify-between items-center text-[9px] text-cyber-muted mb-0.5">
                    <span>{new Date(l.timestamp).toISOString()}</span>
                    <span>IP: {l.ip} ({l.country})</span>
                  </div>
                  <div>
                    <span className={`font-bold mr-2 uppercase ${l.level === 'critical' ? 'text-rose-500 font-extrabold animate-pulse' : l.level === 'error' ? 'text-rose-400' : l.level === 'warning' ? 'text-amber-500' : 'text-blue-400'}`}>
                      [{l.level}][{l.category}]
                    </span>
                    <span className="text-cyber-text">{l.message}</span>
                  </div>
                  {l.details && <div className="text-[9.5px] text-cyber-muted pl-4">➔ {l.details}</div>}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* COMPLIANCE AUDITING PANEL */}
      {activeTab === 'compliance' && (
        <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 space-y-4">
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-cyber-text">Enterprise Compliance & Audits</h3>
          <p className="text-[11px] text-cyber-muted leading-relaxed">
            Real-time compliance validation metrics mapping dynamic ZTNA security architectures to major framework requirements.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
            <div className="bg-cyber-panel border border-cyber-border rounded p-4 text-center">
              <span className="font-mono text-[9px] text-cyber-muted uppercase font-bold">SOC 2 Type II</span>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-2">94% Compliant</p>
              <p className="text-[9px] text-cyber-muted mt-1">Trust Services Criteria verified</p>
            </div>
            <div className="bg-cyber-panel border border-cyber-border rounded p-4 text-center">
              <span className="font-mono text-[9px] text-cyber-muted uppercase font-bold">ISO 27001:2022</span>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-2">91% Compliant</p>
              <p className="text-[9px] text-cyber-muted mt-1">Information Security Controls</p>
            </div>
            <div className="bg-cyber-panel border border-cyber-border rounded p-4 text-center">
              <span className="font-mono text-[9px] text-cyber-muted uppercase font-bold">GDPR Article 32</span>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-2">88% Compliant</p>
              <p className="text-[9px] text-cyber-muted mt-1">Data protection & auditing</p>
            </div>
            <div className="bg-cyber-panel border border-cyber-border rounded p-4 text-center">
              <span className="font-mono text-[9px] text-cyber-muted uppercase font-bold">NIST SP 800-207</span>
              <p className="text-xl font-bold font-mono text-emerald-400 mt-2">90% Compliant</p>
              <p className="text-[9px] text-cyber-muted mt-1">Zero Trust Architecture framework</p>
            </div>
          </div>

          <div className="bg-cyber-panel border border-cyber-border rounded p-4 space-y-3">
            <h4 className="font-mono text-xs font-bold text-cyber-text uppercase tracking-wider">Generate Framework Reports</h4>
            <p className="text-[11px] text-cyber-muted">
              Export comprehensive, time-stamped compliance audit logs including device postures and session authentications.
            </p>
            <div className="flex flex-wrap gap-2.5 pt-1">
              <button
                onClick={() => {
                  addConsoleMessage('[COMPLIANCE] Generated SOC 2 Audit Report PDF Mockup.', 'success');
                  alert('SOC 2 Compliance Report Generated successfully.\nDownload completed: ZTNA_Shield_SOC2_Audit_Report.pdf');
                }}
                className="bg-cyber-primary/10 hover:bg-cyber-primary/20 border border-cyber-primary/30 text-cyber-primary font-mono text-[10px] font-bold uppercase py-2 px-4 rounded transition-all"
              >
                Export SOC 2 Report
              </button>
              <button
                onClick={() => {
                  addConsoleMessage('[COMPLIANCE] Generated ISO 27001 Compliance Report PDF Mockup.', 'success');
                  alert('ISO 27001 Compliance Report Generated successfully.\nDownload completed: ZTNA_Shield_ISO27001_Audit_Report.pdf');
                }}
                className="bg-cyber-secondary/10 hover:bg-cyber-secondary/20 border border-cyber-secondary/30 text-cyber-secondary font-mono text-[10px] font-bold uppercase py-2 px-4 rounded transition-all"
              >
                Export ISO 27001 Report
              </button>
              <button
                onClick={() => {
                  addConsoleMessage('[COMPLIANCE] Generated GDPR Article 32 Audit Report PDF Mockup.', 'success');
                  alert('GDPR Audit Report Generated successfully.\nDownload completed: ZTNA_Shield_GDPR_Compliance_Report.pdf');
                }}
                className="bg-cyber-warning/10 hover:bg-cyber-warning/20 border border-cyber-warning/30 text-cyber-warning font-mono text-[10px] font-bold uppercase py-2 px-4 rounded transition-all"
              >
                Export GDPR Report
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
