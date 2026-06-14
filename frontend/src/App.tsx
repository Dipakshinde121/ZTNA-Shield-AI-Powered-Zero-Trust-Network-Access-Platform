import React, { useState } from 'react';
import { SimulationProvider, useSimulation } from './context/SimulationContext';
import { LoginPortal } from './components/LoginPortal';
import { ClientPortal } from './components/ClientPortal';
import { SOCDashboard } from './components/SOCDashboard';
import { DeviceSimulatorWidget } from './components/DeviceSimulatorWidget';
import { ShieldCheck, Terminal, LogOut } from 'lucide-react';


const AppContent: React.FC = () => {
  const { token, consoleMessages, clearConsole, logout } = useSimulation();
  const [activeTab, setActiveTab] = useState<'client' | 'admin'>('client');
  const [isConsoleOpen, setIsConsoleOpen] = useState(true);

  return (
    <div className="min-h-screen bg-grid-pattern cyber-gradient-bg flex flex-col pb-44 transition-all">
      
      {/* Navigation Header */}
      <header className="bg-cyber-card border-b border-cyber-border sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <ShieldCheck className="w-5 h-5 text-cyber-primary text-glow-green" />
            <span className="font-mono text-xs font-extrabold uppercase tracking-widest text-cyber-text">
              ZTNA-Shield <span className="text-cyber-primary">Control Plane</span>
            </span>
          </div>

          {token && (
            <div className="flex items-center space-x-4">
              <nav className="flex bg-cyber-panel border border-cyber-border rounded p-0.5 font-mono text-[10px] uppercase font-bold">
                <button
                  onClick={() => setActiveTab('client')}
                  className={`px-3 py-1.5 rounded transition-all ${activeTab === 'client' ? 'bg-cyber-primary text-cyber-bg' : 'text-cyber-muted hover:text-cyber-text'}`}
                >
                  Client Access
                </button>
                <button
                  onClick={() => setActiveTab('admin')}
                  className={`px-3 py-1.5 rounded transition-all ${activeTab === 'admin' ? 'bg-cyber-primary text-cyber-bg' : 'text-cyber-muted hover:text-cyber-text'}`}
                >
                  SecOps Admin
                </button>
              </nav>

              <button
                onClick={logout}
                className="text-cyber-muted hover:text-rose-400 p-1.5 rounded border border-transparent hover:border-rose-500/20 hover:bg-rose-500/5 transition-all"
                title="Disconnect Session"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main body viewport */}
      <main className="flex-1 py-8 px-4">
        {token ? (
          activeTab === 'client' ? <ClientPortal /> : <SOCDashboard />
        ) : (
          <LoginPortal onLoginSuccess={() => setActiveTab('client')} />
        )}
      </main>

      {/* Persistent Virtual Device Controller (always accessible) */}
      <DeviceSimulatorWidget />

      {/* Bottom sliding debug/telemetry console */}
      <footer className="fixed bottom-0 left-0 right-0 z-40 bg-cyber-card border-t border-cyber-border shadow-2xl transition-all duration-300">
        <div 
          className="bg-cyber-panel border-b border-cyber-border px-4 py-2 flex items-center justify-between cursor-pointer select-none"
          onClick={() => setIsConsoleOpen(!isConsoleOpen)}
        >
          <div className="flex items-center space-x-2 text-cyber-muted">
            <Terminal className="w-4 h-4 text-cyber-primary" />
            <span className="font-mono text-xs uppercase tracking-wider font-bold">ZTNA Core Telemetry Feed</span>
            <span className="bg-cyber-border text-cyber-muted text-[9px] font-mono px-1 rounded-sm">
              {consoleMessages.length} events
            </span>
          </div>
          <div className="flex items-center space-x-3 text-xs">
            <button 
              onClick={(e) => { e.stopPropagation(); clearConsole(); }}
              className="text-cyber-muted hover:text-cyber-text font-mono text-[9px] uppercase tracking-wider border border-cyber-border px-1.5 py-0.5 rounded bg-cyber-bg"
            >
              Clear
            </button>
            <span className="text-cyber-muted">{isConsoleOpen ? '▼ Hide' : '▲ Show'}</span>
          </div>
        </div>

        {isConsoleOpen && (
          <div className="h-32 overflow-y-auto bg-[#040508] p-3 font-mono text-[10px] space-y-1">
            {consoleMessages.length === 0 ? (
              <p className="text-cyber-muted italic text-center pt-8">No security telemetry events captured yet. Modify device specification or log in to trigger events.</p>
            ) : (
              consoleMessages.map(msg => (
                <div key={msg.id} className="flex items-start space-x-2 leading-relaxed border-b border-cyber-border/20 pb-0.5">
                  <span className="text-cyber-muted flex-shrink-0">[{msg.timestamp}]</span>
                  {msg.type === 'success' && <span className="text-emerald-400 font-semibold">[OK]</span>}
                  {msg.type === 'warn' && <span className="text-amber-400 font-semibold">[WARN]</span>}
                  {msg.type === 'error' && <span className="text-rose-400 font-semibold">[FAIL]</span>}
                  {msg.type === 'cyber' && <span className="text-cyan-400 font-semibold">[AI/TELEMETRY]</span>}
                  {msg.type === 'info' && <span className="text-blue-400 font-semibold">[SYS]</span>}
                  <span className="text-cyber-text">{msg.message}</span>
                </div>
              ))
            )}
          </div>
        )}
      </footer>

    </div>
  );
};

function App() {
  return (
    <SimulationProvider>
      <AppContent />
    </SimulationProvider>
  );
}

export default App;
