// Redirects to SystemsPage — agents are now called "systems"
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function AgentsPage() {
  const navigate = useNavigate();
  useEffect(() => { navigate('/systems', { replace: true }); }, [navigate]);
  return null;
}
