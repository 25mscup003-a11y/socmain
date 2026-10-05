import { authStorage, incomingImpersonationToken } from '../api/authStorage';
import { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/axios';
import { getCachedBrowserLocation } from '../utils/browserLocation';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [impersonation, setImpersonation] = useState(null);

  useEffect(() => {
    const impersonationToken = incomingImpersonationToken
      || (authStorage.getItem('sa_impersonation') && authStorage.getItem('sa_token'));
    if (impersonationToken) {
      api.get('/auth/me').then(({ data }) => {
        if (data.user?.role !== 'superadmin' || !data.impersonation?.active) throw new Error('Invalid Superadmin session');
        authStorage.setItem('sa_token', data.token);
        authStorage.setItem('sa_user', JSON.stringify(data.user));
        authStorage.setItem('sa_impersonation', JSON.stringify(data.impersonation));
        api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
        setUser(data.user);
        setImpersonation(data.impersonation);
      }).catch(() => {
        ['sa_token', 'sa_user', 'sa_impersonation'].forEach(key => authStorage.removeItem(key));
        delete api.defaults.headers.common['Authorization'];
      }).finally(() => setLoading(false));
      return;
    }
    const token = authStorage.getItem('sa_token');
    const saved  = authStorage.getItem('sa_user');
    if (token && saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.role === 'superadmin') {
          setUser(parsed);
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          authStorage.removeItem('sa_token');
          authStorage.removeItem('sa_user');
        }
      } catch (err) {
        authStorage.removeItem('sa_token');
        authStorage.removeItem('sa_user');
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
    
    authStorage.setItem('sa_token', data.token);
    authStorage.setItem('sa_user',  JSON.stringify(data.user));
    authStorage.removeItem('sa_impersonation');
    setImpersonation(null);
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
    setUser(data.user);
    return data;
  };

  const logout = () => {
    const token = authStorage.getItem('sa_token');
    const logoutRequest = token
      ? api.post('/auth/logout', { reason: 'manual', location: getCachedBrowserLocation() }, {
        headers: { Authorization: `Bearer ${token}` }, timeout: 10000,
      }).catch(() => null)
      : Promise.resolve(null);
    authStorage.removeItem('sa_token');
    authStorage.removeItem('sa_user');
    authStorage.removeItem('sa_impersonation');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
    setImpersonation(null);
    return logoutRequest;
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading, impersonation }}>
      {impersonation?.active && user && (
        <div role="status" style={{ padding: '10px 18px', background: '#7f1d1d', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, fontSize: 13 }}>
          <span>{impersonation.banner || `Logged in as ${user.email} via Super Admin`}</span>
          <button type="button" onClick={async () => { await logout(); window.close(); window.location.replace('/login'); }}
            style={{ padding: '7px 12px', border: '1px solid #fca5a5', borderRadius: 6, background: 'transparent', color: '#fff', cursor: 'pointer' }}>
            End user session
          </button>
        </div>
      )}
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
