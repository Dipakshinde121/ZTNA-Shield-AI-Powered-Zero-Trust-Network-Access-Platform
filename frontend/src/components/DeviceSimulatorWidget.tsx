import React, { useState } from 'react';
import { useSimulation } from '../context/SimulationContext';
import { Shield, Cpu, Globe, Sliders } from 'lucide-react';

export const DeviceSimulatorWidget: React.FC = () => {
  const { simulatedDevice, updateSimulatedDevice, deviceStatus } = useSimulation();
  const [isOpen, setIsOpen] = useState(true);

  const countries = [
    { code: 'US', name: 'United States' },
    { code: 'GB', name: 'United Kingdom' },
    { code: 'IN', name: 'India' },
    { code: 'DE', name: 'Germany' },
    { code: 'RU', name: 'Russia (High Risk)' },
    { code: 'CN', name: 'China (High Risk)' },
    { code: 'KP', name: 'North Korea (Blocked)' }
  ];

  const operatingSystems = [
    { name: 'Windows 11', type: 'modern' },
    { name: 'macOS Ventura', type: 'modern' },
    { name: 'Linux Kernel 6.2', type: 'modern' },
    { name: 'Windows 7 (Legacy)', type: 'vulnerable' }
  ];

  return (
    <div className={`fixed bottom-4 right-4 z-50 bg-cyber-card border border-cyber-border rounded-lg shadow-cyber-glow transition-all duration-300 w-80 max-h-[85vh] overflow-y-auto ${isOpen ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-90'}`}>
      
      {/* Header bar */}
      <div className="flex items-center justify-between p-3 border-b border-cyber-border bg-cyber-panel cursor-pointer select-none" onClick={() => setIsOpen(!isOpen)}>
        <div className="flex items-center space-x-2 text-cyber-primary">
          <Sliders className="w-4 h-4" />
          <span className="font-mono text-xs font-bold uppercase tracking-wider">Device Trust Simulator</span>
        </div>
        <div className="flex items-center space-x-2">
          {deviceStatus === 'Trusted' && <span className="bg-emerald-500/10 text-emerald-400 text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/20">TRUSTED</span>}
          {deviceStatus === 'Unknown' && <span className="bg-amber-500/10 text-amber-400 text-[10px] font-mono px-1.5 py-0.5 rounded border border-amber-500/20">UNKNOWN</span>}
          {deviceStatus === 'Compromised' && <span className="bg-rose-500/10 text-rose-400 text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-500/20">COMPROMISED</span>}
          {deviceStatus === 'Blocked' && <span className="bg-red-500/20 text-red-500 text-[10px] font-mono px-1.5 py-0.5 rounded border border-red-500/30">BLOCKED</span>}
          <button className="text-cyber-muted hover:text-cyber-text text-xs">{isOpen ? '▼' : '▲'}</button>
        </div>
      </div>

      {isOpen && (
        <div className="p-4 space-y-4 font-sans text-xs">
          <p className="text-cyber-muted leading-relaxed text-[11px]">
            Adjust this virtual machine's specifications below. The ZTNA Gateway continuously intercepts modifications to recalculate security scores.
          </p>

          {/* Endpoint Posture Toggles */}
          <div className="space-y-2.5">
            <h4 className="font-mono text-[10px] uppercase tracking-wider text-cyber-primary border-b border-cyber-border pb-1 flex items-center">
              <Shield className="w-3.5 h-3.5 mr-1" /> Posture Security Agents
            </h4>

            {/* Antivirus */}
            <div className="flex items-center justify-between">
              <span className="text-cyber-text flex items-center">
                Antivirus Agent Active
              </span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={simulatedDevice.antivirus} 
                  onChange={(e) => updateSimulatedDevice({ antivirus: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-cyber-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-muted after:border-gray-300 after:border after:rounded-full after:height-3 after:h-3 after:w-3 after:transition-all peer-checked:bg-cyber-primary peer-checked:after:bg-cyber-bg"></div>
              </label>
            </div>

            {/* Firewall */}
            <div className="flex items-center justify-between">
              <span className="text-cyber-text">Firewall Active</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={simulatedDevice.firewall} 
                  onChange={(e) => updateSimulatedDevice({ firewall: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-cyber-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-muted after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-cyber-primary peer-checked:after:bg-cyber-bg"></div>
              </label>
            </div>

            {/* Disk Encryption */}
            <div className="flex items-center justify-between">
              <span className="text-cyber-text">Disk Encryption Enabled</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={simulatedDevice.diskEncryption} 
                  onChange={(e) => updateSimulatedDevice({ diskEncryption: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-cyber-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-muted after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-cyber-primary peer-checked:after:bg-cyber-bg"></div>
              </label>
            </div>
          </div>

          {/* Network Parameters */}
          <div className="space-y-2.5">
            <h4 className="font-mono text-[10px] uppercase tracking-wider text-cyber-secondary border-b border-cyber-border pb-1 flex items-center">
              <Globe className="w-3.5 h-3.5 mr-1" /> Network Context
            </h4>

            {/* Simulated VPN */}
            <div className="flex items-center justify-between">
              <span className="text-cyber-text flex items-center">
                VPN Proxy Connection
              </span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={simulatedDevice.isVPN} 
                  onChange={(e) => updateSimulatedDevice({ isVPN: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-cyber-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-muted after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-cyber-secondary peer-checked:after:bg-cyber-bg"></div>
              </label>
            </div>

            {/* Tor Exit node */}
            <div className="flex items-center justify-between">
              <span className="text-cyber-text">Tor Router Encapsulated</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={simulatedDevice.isTor} 
                  onChange={(e) => updateSimulatedDevice({ isTor: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-8 h-4 bg-cyber-border peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-cyber-muted after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-cyber-secondary peer-checked:after:bg-cyber-bg"></div>
              </label>
            </div>

            {/* Country */}
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-cyber-text">Geographic Location</span>
                <span className="text-cyber-secondary font-mono font-semibold">{simulatedDevice.country}</span>
              </div>
              <select
                value={simulatedDevice.country}
                onChange={(e) => updateSimulatedDevice({ country: e.target.value })}
                className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-1.5 rounded focus:outline-none focus:border-cyber-secondary text-[11px] font-mono"
              >
                {countries.map(c => (
                  <option key={c.code} value={c.code}>{c.name}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Machine OS Configuration */}
          <div className="space-y-2.5">
            <h4 className="font-mono text-[10px] uppercase tracking-wider text-amber-500 border-b border-cyber-border pb-1 flex items-center">
              <Cpu className="w-3.5 h-3.5 mr-1" /> OS Platform
            </h4>
            
            <div className="space-y-1">
              <select
                value={simulatedDevice.os}
                onChange={(e) => updateSimulatedDevice({ os: e.target.value })}
                className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-1.5 rounded focus:outline-none focus:border-amber-500 text-[11px] font-mono"
              >
                {operatingSystems.map(os => (
                  <option key={os.name} value={os.name}>{os.name}</option>
                ))}
              </select>
            </div>
            
            <div className="space-y-1">
              <span className="text-cyber-muted">Device Hostname</span>
              <input
                type="text"
                value={simulatedDevice.hostname}
                onChange={(e) => updateSimulatedDevice({ hostname: e.target.value })}
                className="w-full bg-cyber-bg border border-cyber-border text-cyber-text p-1.5 rounded focus:outline-none focus:border-cyber-primary text-[11px] font-mono"
              />
            </div>
          </div>

          {/* Preset templates */}
          <div className="pt-2 border-t border-cyber-border flex space-x-2">
            <button
              onClick={() => {
                updateSimulatedDevice({
                  antivirus: true,
                  firewall: true,
                  diskEncryption: true,
                  isVPN: false,
                  isTor: false,
                  country: 'US',
                  os: 'Windows 11'
                });
              }}
              className="flex-1 bg-emerald-500/10 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-400 font-mono py-1 rounded transition-colors text-[9px] uppercase font-bold"
            >
              Secure PC
            </button>
            <button
              onClick={() => {
                updateSimulatedDevice({
                  antivirus: false,
                  firewall: false,
                  diskEncryption: false,
                  isVPN: true,
                  isTor: true,
                  country: 'RU',
                  os: 'Windows 7 (Legacy)'
                });
              }}
              className="flex-1 bg-rose-500/10 hover:bg-rose-500/25 border border-rose-500/30 text-rose-400 font-mono py-1 rounded transition-colors text-[9px] uppercase font-bold"
            >
              Compromise
            </button>
          </div>

        </div>
      )}
    </div>
  );
};
