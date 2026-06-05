import React, { createContext, useContext, useState, useEffect } from 'react';
import { getDeviceFingerprint } from '../utils/fingerprint';

export interface SimulatedDevice {
  diskEncryption: boolean;
  firewall: boolean;
  antivirus: boolean;
  isVPN: boolean;
  isTor: boolean;
  country: string;
  os: string;
  browser: string;
  hostname: string;
  macHash: string;
  fingerprint: string;
}

interface ConsoleMessage {
  id: string;
  timestamp: string;
  type: 'info' | 'success' | 'warn' | 'error' | 'cyber';
  message: string;
}

interface SimulationContextType {
  simulatedDevice: SimulatedDevice;
  updateSimulatedDevice: (updates: Partial<SimulatedDevice>) => void;
  token: string | null;
  refreshToken: string | null;
  user: any | null;
  deviceStatus: 'Trusted' | 'Unknown' | 'Compromised' | 'Blocked';
  deviceId: string | null;
  setAuthData: (token: string | null, refreshToken: string | null, user: any, deviceStatus: 'Trusted' | 'Unknown' | 'Compromised' | 'Blocked', deviceId: string | null) => void;
  logout: () => Promise<void>;
  consoleMessages: ConsoleMessage[];
  addConsoleMessage: (message: string, type?: ConsoleMessage['type']) => void;
  clearConsole: () => void;
}

const SimulationContext = createContext<SimulationContextType | undefined>(undefined);

export const SimulationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const initialFingerprint = getDeviceFingerprint();
  
  const [simulatedDevice, setSimulatedDevice] = useState<SimulatedDevice>({
    diskEncryption: true,
    firewall: true,
    antivirus: true,
    isVPN: false,
    isTor: false,
    country: 'US',
    os: initialFingerprint.os,
    browser: initialFingerprint.browser,
    hostname: 'shield-workstation-01',
    macHash: 'a1:b2:c3:d4:e5:f6',
    fingerprint: initialFingerprint.canvasHash
  });

  const [token, setToken] = useState<string | null>(localStorage.getItem('ztna_token'));
  const [refreshToken, setRefreshToken] = useState<string | null>(localStorage.getItem('ztna_refresh'));
  const [user, setUser] = useState<any | null>(null);
  const [deviceStatus, setDeviceStatus] = useState<'Trusted' | 'Unknown' | 'Compromised' | 'Blocked'>('Unknown');
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [consoleMessages, setConsoleMessages] = useState<ConsoleMessage[]>([]);

  // Parse user from token if available on load
  useEffect(() => {
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUser({ id: payload.userId, email: payload.email, role: payload.role });
      } catch (e) {
        // Token invalid
        setToken(null);
        setRefreshToken(null);
        localStorage.removeItem('ztna_token');
        localStorage.removeItem('ztna_refresh');
      }
    }
  }, [token]);

  const addConsoleMessage = (message: string, type: ConsoleMessage['type'] = 'info') => {
    const newMsg: ConsoleMessage = {
      id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      timestamp: new Date().toLocaleTimeString(),
      type,
      message
    };
    setConsoleMessages(prev => [newMsg, ...prev].slice(0, 100)); // Cap at 100 messages
  };

  const clearConsole = () => setConsoleMessages([]);

  const updateSimulatedDevice = (updates: Partial<SimulatedDevice>) => {
    setSimulatedDevice(prev => {
      const next = { ...prev, ...updates };
      addConsoleMessage(`Device profile updated: ${Object.keys(updates).map(k => `${k}=${(updates as any)[k]}`).join(', ')}`, 'warn');
      return next;
    });
  };

  const setAuthData = (
    newToken: string | null,
    newRefreshToken: string | null,
    newUser: any,
    newDeviceStatus: 'Trusted' | 'Unknown' | 'Compromised' | 'Blocked',
    newDeviceId: string | null
  ) => {
    setToken(newToken);
    setRefreshToken(newRefreshToken);
    setUser(newUser);
    setDeviceStatus(newDeviceStatus);
    setDeviceId(newDeviceId);

    if (newToken) {
      localStorage.setItem('ztna_token', newToken);
    } else {
      localStorage.removeItem('ztna_token');
    }

    if (newRefreshToken) {
      localStorage.setItem('ztna_refresh', newRefreshToken);
    } else {
      localStorage.removeItem('ztna_refresh');
    }
  };

  const logout = async () => {
    if (token) {
      try {
        await fetch('http://localhost:5000/api/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
      } catch (e) {
        console.error('Logout request failed', e);
      }
    }
    
    setAuthData(null, null, null, 'Unknown', null);
    addConsoleMessage('Session cleared. User logged out.', 'info');
  };

  return (
    <SimulationContext.Provider value={{
      simulatedDevice,
      updateSimulatedDevice,
      token,
      refreshToken,
      user,
      deviceStatus,
      deviceId,
      setAuthData,
      logout,
      consoleMessages,
      addConsoleMessage,
      clearConsole
    }}>
      {children}
    </SimulationContext.Provider>
  );
};

export const useSimulation = () => {
  const context = useContext(SimulationContext);
  if (!context) throw new Error('useSimulation must be used within a SimulationProvider');
  return context;
};
