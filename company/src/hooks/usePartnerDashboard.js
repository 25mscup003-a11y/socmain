import { useCallback, useEffect, useRef, useState } from 'react';
import api from '../api/axios';
import { io, SOCKET_URL, connectSocket } from '../api/config';

export default function usePartnerDashboard(partnerId) {
  const [stats, setStats] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const refreshRef = useRef(() => {});
  const refresh = useCallback(() => refreshRef.current(), []);

  useEffect(() => {
    if (!partnerId) return undefined;
    let disposed = false;
    let running = false;
    let queued = false;
    let debounce;
    setStats(null);
    setError('');
    setLastUpdated(null);

    const load = async () => {
      if (disposed) return;
      if (running) { queued = true; return; }
      running = true;
      setRefreshing(true);
      try {
        const { data } = await api.get('/partner/dashboard', { skipCache: true });
        if (data.partial || !data.partner) throw new Error('Incomplete dashboard');
        if (!disposed) {
          setStats(data);
          setLastUpdated(data.updatedAt || new Date().toISOString());
          setError('');
        }
      } catch (err) {
        if (!disposed) setError(err.response?.data?.message || 'Unable to refresh. Previously loaded data is still shown.');
      } finally {
        running = false;
        if (!disposed) {
          setRefreshing(false);
          if (queued) { queued = false; schedule(); }
        }
      }
    };
    const schedule = () => {
      clearTimeout(debounce);
      debounce = setTimeout(load, 250);
    };
    const onUpdate = event => {
      if (!event?.partnerId || String(event.partnerId) === String(partnerId)) schedule();
    };
    const onVisible = () => { if (document.visibilityState === 'visible') schedule(); };
    const socket = io(SOCKET_URL);
    const onConnect = () => {
      setConnected(true);
      socket.emit('join:partner', partnerId);
      schedule();
    };
    const onDisconnect = () => setConnected(false);
    socket.emit('join:partner', partnerId);
    setConnected(socket.connected);
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onDisconnect);
    socket.on('partner:update', onUpdate);
    const disconnect = connectSocket(socket);
    const interval = setInterval(onVisible, 30000);
    window.addEventListener('focus', onVisible);
    document.addEventListener('visibilitychange', onVisible);
    refreshRef.current = load;
    load();
    return () => {
      disposed = true;
      clearTimeout(debounce);
      clearInterval(interval);
      refreshRef.current = () => {};
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onDisconnect);
      socket.off('partner:update', onUpdate);
      window.removeEventListener('focus', onVisible);
      document.removeEventListener('visibilitychange', onVisible);
      disconnect();
    };
  }, [partnerId]);

  return { stats, setStats, refreshing, error, connected, lastUpdated, refresh };
}
