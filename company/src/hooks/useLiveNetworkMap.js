import { useCallback, useEffect, useState } from 'react';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';

export default function useLiveNetworkMap(companyId, enabled = true) {
  const [connections, setConnections] = useState([]);
  const [agents, setAgents] = useState([]);
  const [total, setTotal] = useState(0);
  const [directionCounts, setDirectionCounts] = useState({ inbound: 0, outbound: 0, internal: 0, unknown: 0 });
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async (quiet = false) => {
    if (!enabled) return;
    if (!quiet) setLoading(true);
    try {
      const { data } = await api.get('/network/live-map', {
        params: { hours: 24, ...(companyId ? { companyId: String(companyId) } : {}) },
        skipCache: true,
      });
      setConnections(Array.isArray(data?.connections) ? data.connections : []);
      setAgents(Array.isArray(data?.agents) ? data.agents : []);
      setTotal(Number(data?.total || 0));
      setDirectionCounts(data?.directionCounts || { inbound: 0, outbound: 0, internal: 0, unknown: 0 });
    } catch {
      if (!quiet) {
        setConnections([]);
        setAgents([]);
        setTotal(0);
      }
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [companyId, enabled]);

  useEffect(() => {
    if (!enabled) return undefined;
    refresh(false);
    const poll = setInterval(() => refresh(true), 10000);
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    let timer = null;
    const scheduleRefresh = () => {
      clearTimeout(timer);
      timer = setTimeout(() => refresh(true), 350);
    };
    socket.on('connect', join);
    socket.on('network:event', scheduleRefresh);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      clearInterval(poll);
      clearTimeout(timer);
      socket.off('connect', join);
      socket.off('network:event', scheduleRefresh);
      disconnect();
    };
  }, [companyId, enabled, refresh]);

  return { connections, agents, total, directionCounts, loading, refresh };
}
