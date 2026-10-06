import { authStorage, incomingImpersonationToken } from '../api/authStorage';
import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios';
import { getCachedBrowserLocation } from '../utils/browserLocation';

const AuthContext = createContext(null);
const SCREEN_LOCK_MS = 10 * 60 * 1000;
const AUTO_LOGOUT_MS = 30 * 60 * 1000;

export function AuthProvider({ children }) {
  const [user,            setUser]            = useState(null);
  const [company,         setCompany]         = useState(null);
  const [impersonation,   setImpersonation]   = useState(null);
  const [loading,         setLoading]         = useState(true);
  const [selectedDeptId,  setSelectedDeptId]  = useState(null); // analyst multi-dept
  const [sessionLocked,   setSessionLocked]   = useState(false);
  const [idleLogoutSeconds, setIdleLogoutSeconds] = useState(0);
  const lastActivityRef = useRef(Date.now());
  const lockedRef = useRef(false);
  const autoLogoutRef = useRef(false);
  const lastPersistedActivityRef = useRef(0);

  useEffect(() => {
    const impersonationToken = incomingImpersonationToken
      || (authStorage.getItem('co_impersonation') && authStorage.getItem('co_token'));
    if (impersonationToken) {
      authStorage.setItem('co_token', impersonationToken);
      authStorage.setItem('co_impersonation', JSON.stringify({
        active: true,
        banner: 'You are logged in through a support session',
      }));
      api.defaults.headers.common['Authorization'] = `Bearer ${impersonationToken}`;
      api.get('/auth/me')
        .then(({ data }) => {
          if (!data.user || data.user.role === 'superadmin') throw new Error('Invalid company session');
          const partnerUser = data.user;
          if (data.token) {
            authStorage.setItem('co_token', data.token);
            api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
          }
          authStorage.setItem('co_user', JSON.stringify(partnerUser));
          if (data.company) authStorage.setItem('co_company', JSON.stringify(data.company));
          else authStorage.removeItem('co_company');
          setUser(partnerUser);
          setCompany(data.company || null);
          authStorage.setItem('co_impersonation', JSON.stringify(data.impersonation));
          setImpersonation(data.impersonation);
        })
        .catch((error) => {
          if (error.response?.status === 401 || error.response?.status === 404 || error.message === 'Invalid company session') {
            authStorage.removeItem('co_token');
            authStorage.removeItem('co_user');
            authStorage.removeItem('co_impersonation');
            authStorage.removeItem('co_company');
            delete api.defaults.headers.common['Authorization'];
          }
        })
        .finally(() => setLoading(false));
      return;
    }

    const token     = authStorage.getItem('co_token');
    const savedUser = authStorage.getItem('co_user');
    const savedCo   = authStorage.getItem('co_company');
    const savedImp   = authStorage.getItem('co_impersonation');
    if (token && savedUser) {
      const parsed = JSON.parse(savedUser);
      if (parsed.role !== 'superadmin') {
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        api.get('/auth/me')
          .then(({ data }) => {
            if (!data?.user || data.user.role === 'superadmin') throw new Error('Invalid company session');
            if (data.token) {
              authStorage.setItem('co_token', data.token);
              api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
            }
            authStorage.setItem('co_user', JSON.stringify(data.user));
            setUser(data.user);
            if (data.company) {
              authStorage.setItem('co_company', JSON.stringify(data.company));
              setCompany(data.company);
            } else if (savedCo) setCompany(JSON.parse(savedCo));
            setImpersonation(data.impersonation || null);
          })
          .catch((error) => {
            const sessionRejected = error.response?.status === 401 || error.response?.status === 404;
            if (sessionRejected || error.message === 'Invalid company session') {
              ['co_token','co_user','co_company','co_impersonation'].forEach(key => authStorage.removeItem(key));
              delete api.defaults.headers.common['Authorization'];
              setUser(null); setCompany(null); setImpersonation(null);
              return;
            }
            // Preserve the cached identity during a temporary backend/network
            // failure; the next authenticated request will validate it again.
            setUser(parsed);
            if (savedCo) setCompany(JSON.parse(savedCo));
            if (savedImp) setImpersonation(JSON.parse(savedImp));
          })
          .finally(() => setLoading(false));
        return;
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password, location) => {
    const { data } = await api.post('/auth/login', { email, password, location });
    if (data.user.role === 'superadmin')
      throw new Error('Use the superadmin portal to sign in');
    authStorage.setItem('co_token',   data.token);
    authStorage.setItem('co_user',    JSON.stringify(data.user));
    if (data.company) authStorage.setItem('co_company', JSON.stringify(data.company));
    authStorage.removeItem('co_impersonation');
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
    authStorage.setItem(`soc_last_activity:${data.user._id || data.user.id}`, String(Date.now()));
    authStorage.removeItem(`soc_session_locked:${data.user._id || data.user.id}`);
    setUser(data.user);
    setCompany(data.company || null);
    setImpersonation(null);
    return data;
  };

  // Load auth data from localStorage (call after login to update context)
  const loadFromStorage = () => {
    const token     = authStorage.getItem('co_token');
    const savedUser = authStorage.getItem('co_user');
    const savedCo   = authStorage.getItem('co_company');
    if (token && savedUser) {
      const parsed = JSON.parse(savedUser);
      setUser(parsed);
      if (savedCo) setCompany(JSON.parse(savedCo));
      const savedImp = authStorage.getItem('co_impersonation');
      setImpersonation(savedImp ? JSON.parse(savedImp) : null);
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
  };

  // ✅ FIX: Fetch fresh company data from server and update both state + localStorage
  // Call this after payment confirmation to ensure plan is reflected immediately
  const refreshCompany = useCallback(async () => {
    try {
      const { data } = await api.get('/payment/status');
      if (data) {
        setCompany(data);
        authStorage.setItem('co_company', JSON.stringify(data));
      }
    } catch (err) {
      console.error('[AuthContext] refreshCompany failed:', err.message);
    }
  }, []);

  const logout = useCallback(({ reason = 'manual' } = {}) => {
    const accountId = user?._id || user?.id;
    const token = authStorage.getItem('co_token');
    const logoutRequest = token
      ? api.post('/auth/logout', { reason, location: getCachedBrowserLocation() }, {
        headers: { Authorization: `Bearer ${token}` }, timeout: 10000,
      }).catch(() => null)
      : Promise.resolve(null);
    ['co_token','co_user','co_company','co_tenant','co_impersonation'].forEach(k => authStorage.removeItem(k));
    if (accountId) {
      authStorage.removeItem(`soc_last_activity:${accountId}`);
      authStorage.removeItem(`soc_session_locked:${accountId}`);
    }
    try { sessionStorage.removeItem('partner_plan'); } catch {}
    delete api.defaults.headers.common['Authorization'];
    lockedRef.current = false;
    autoLogoutRef.current = false;
    setSessionLocked(false);
    setUser(null);
    setCompany(null);
    setImpersonation(null);
    return logoutRequest;
  }, [user?._id, user?.id]);

  const resumeLockedSession = useCallback(async () => {
    const accountId = user?._id || user?.id;
    if (!accountId || !lockedRef.current) return;
    await api.post('/auth/session-event', { action: 'screen_unlocked', reason: 'user_resumed_activity' }).catch(() => null);
    const now = Date.now();
    lastActivityRef.current = now;
    lastPersistedActivityRef.current = now;
    authStorage.setItem(`soc_last_activity:${accountId}`, String(now));
    authStorage.removeItem(`soc_session_locked:${accountId}`);
    lockedRef.current = false;
    setSessionLocked(false);
    setIdleLogoutSeconds(0);
  }, [user?._id, user?.id]);

  const lockSessionNow = useCallback((reason = 'manual_screen_lock') => {
    const accountId = user?._id || user?.id;
    if (!accountId || lockedRef.current || autoLogoutRef.current) return;
    const lockedAt = Date.now();
    if (reason === 'manual_screen_lock') {
      lastActivityRef.current = lockedAt;
      lastPersistedActivityRef.current = lockedAt;
      authStorage.setItem(`soc_last_activity:${accountId}`, String(lockedAt));
    }
    lockedRef.current = true;
    authStorage.setItem(`soc_session_locked:${accountId}`, String(lockedAt));
    setSessionLocked(true);
    api.post('/auth/session-event', { action: 'screen_locked', reason }).catch(() => null);
  }, [user?._id, user?.id]);

  useEffect(() => {
    const accountId = user?._id || user?.id;
    if (!accountId) return undefined;
    const activityKey = `soc_last_activity:${accountId}`;
    const lockKey = `soc_session_locked:${accountId}`;
    const storedActivity = Number(authStorage.getItem(activityKey));
    const now = Date.now();
    lastActivityRef.current = Number.isFinite(storedActivity) && storedActivity > 0 ? storedActivity : now;
    lastPersistedActivityRef.current = lastActivityRef.current;
    if (!storedActivity) authStorage.setItem(activityKey, String(now));
    const storedLock = Number(authStorage.getItem(lockKey));
    lockedRef.current = Number.isFinite(storedLock) && storedLock > 0;
    setSessionLocked(lockedRef.current);
    autoLogoutRef.current = false;

    const checkIdle = () => {
      const idleMs = Math.max(0, Date.now() - lastActivityRef.current);
      if (idleMs >= AUTO_LOGOUT_MS && !autoLogoutRef.current) {
        autoLogoutRef.current = true;
        setIdleLogoutSeconds(0);
        logout({ reason: 'inactivity' }).finally(() => {
          window.location.assign('/login?reason=inactivity');
        });
        return;
      }
      if (idleMs >= SCREEN_LOCK_MS) lockSessionNow('idle_timeout_10m');
      setIdleLogoutSeconds(lockedRef.current ? Math.max(0, Math.ceil((AUTO_LOGOUT_MS - idleMs) / 1000)) : 0);
    };

    const recordActivity = () => {
      if (lockedRef.current || autoLogoutRef.current) return;
      const activityAt = Date.now();
      lastActivityRef.current = activityAt;
      if (activityAt - lastPersistedActivityRef.current >= 5000) {
        lastPersistedActivityRef.current = activityAt;
        authStorage.setItem(activityKey, String(activityAt));
      }
    };
    const syncAcrossTabs = event => {
      if (authStorage === sessionStorage) return;
      if (event.key === activityKey && event.newValue && !lockedRef.current) {
        lastActivityRef.current = Number(event.newValue) || Date.now();
      }
      if (event.key === lockKey) {
        lockedRef.current = Boolean(event.newValue);
        setSessionLocked(Boolean(event.newValue));
      }
    };
    const activityEvents = ['pointerdown', 'mousemove', 'keydown', 'touchstart', 'scroll'];
    activityEvents.forEach(eventName => window.addEventListener(eventName, recordActivity, { passive: true }));
    window.addEventListener('storage', syncAcrossTabs);
    document.addEventListener('visibilitychange', checkIdle);
    const timer = window.setInterval(checkIdle, 5000);
    checkIdle();
    return () => {
      activityEvents.forEach(eventName => window.removeEventListener(eventName, recordActivity));
      window.removeEventListener('storage', syncAcrossTabs);
      document.removeEventListener('visibilitychange', checkIdle);
      window.clearInterval(timer);
    };
  }, [user?._id, user?.id, logout, lockSessionNow]);

  // Roles: 'company_admin' | 'department_admin' | 'analyst'
  const isAdmin     = user?.role === 'company_admin' || user?.role === 'partner_admin';
  const isDeptAdmin = user?.role === 'department_admin';
  const isAnalyst   = ['analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(user?.role);
  const isManager   = ['company_admin', 'department_admin', 'soc_manager'].includes(user?.role);

  return (
    <AuthContext.Provider value={{
      user, company, setCompany, login, logout, lockSession: () => lockSessionNow('manual_screen_lock'), loadFromStorage, refreshCompany, loading,
      impersonation, isImpersonating: !!impersonation?.active,
      isAdmin, isDeptAdmin, isAnalyst, isManager,
      selectedDeptId, setSelectedDeptId,
    }}>
      {impersonation?.active && user && (
        <div role="status" style={{ padding: '10px 18px', background: '#7f1d1d', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, fontSize: 13 }}>
          <span>{impersonation.banner || `Logged in as ${user.email} through a support session`}</span>
          <button type="button" onClick={async () => { await logout(); window.close(); window.location.replace('/login'); }}
            style={{ padding: '7px 12px', border: '1px solid #fca5a5', borderRadius: 6, background: 'transparent', color: '#fff', cursor: 'pointer' }}>
            End user session
          </button>
        </div>
      )}
      {children}
      {user && sessionLocked && (
        <div role="dialog" aria-modal="true" aria-label="Session locked" style={sessionLockBackdrop}>
          <div style={sessionLockCard}>
            <div style={{ fontSize: 34, marginBottom: 8 }}>🔐</div>
            <h2 style={{ margin: 0, color: '#f8fafc', fontSize: 22 }}>Screen Locked</h2>
            <p style={{ margin: '10px 0 6px', color: '#94a3b8', lineHeight: 1.55 }}>
              This session was locked manually or because no dashboard, keyboard or mouse activity was detected for 10 minutes.
            </p>
            <p style={{ margin: '0 0 18px', color: '#facc15', fontSize: 12 }}>
              Automatic logout in {Math.max(0, Math.ceil(idleLogoutSeconds / 60))} minute(s).
            </p>
            <button type="button" autoFocus onClick={resumeLockedSession} style={resumeButton}>Resume Session</button>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

const sessionLockBackdrop = {
  position: 'fixed', inset: 0, zIndex: 99999, display: 'grid', placeItems: 'center',
  padding: 20, background: 'rgba(2,6,23,.94)', backdropFilter: 'blur(10px)',
};
const sessionLockCard = {
  width: 'min(430px,100%)', padding: 30, textAlign: 'center', borderRadius: 16,
  background: 'linear-gradient(145deg,#0c192c,#101d35)', border: '1px solid #294765',
  boxShadow: '0 30px 90px rgba(0,0,0,.55)', fontFamily: 'Inter,system-ui,sans-serif',
};
const resumeButton = {
  width: '100%', padding: '11px 16px', borderRadius: 9, border: '1px solid #2563eb',
  background: '#1d4ed8', color: '#fff', fontWeight: 800, cursor: 'pointer',
};
