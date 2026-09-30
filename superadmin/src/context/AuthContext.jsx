import { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/axios';
import { getCachedBrowserLocation } from '../utils/browserLocation';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('sa_token');
    const saved  = localStorage.getItem('sa_user');
    if (token && saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.role === 'superadmin') {
          setUser(parsed);
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          localStorage.removeItem('sa_token');
          localStorage.removeItem('sa_user');
        }
      } catch (err) {
        localStorage.removeItem('sa_token');
        localStorage.removeItem('sa_user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password, location, telemetry_id) => {
    const { data } = await api.post('/auth/login', { email, password, location, telemetry_id });
    
    // Check if response indicates OTP is required (unverified email)
    if (data.requiresOTP) {
      const error = new Error(data.message);
      error.requiresOTP = true;
      error.email = data.email;
      throw error;
    }

    // Check if 2FA is required — let LoginPage handle the TOTP screen
    if (data.requires2FA) {
      const error = new Error(data.message || '2FA required');
      error.requires2FA = true;
      error.email = data.email;
      throw error;
    }
    
    if (!data || !data.user || data.user.role !== 'superadmin') {
      throw new Error('Access denied: use the company/partner portal to sign in');
    }
    
    localStorage.setItem('sa_token', data.token);
    localStorage.setItem('sa_user',  JSON.stringify(data.user));
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
    setUser(data.user);
    return data;
  };

  const logout = () => {
    const logoutRequest = localStorage.getItem('sa_token')
      ? api.post('/auth/logout', { reason: 'manual', location: getCachedBrowserLocation() }).catch(() => null)
      : Promise.resolve(null);
    localStorage.removeItem('sa_token');
    localStorage.removeItem('sa_user');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
    return logoutRequest;
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
