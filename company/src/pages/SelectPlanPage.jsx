/**
 * SelectPlanPage — Redirects to the payments page.
 * Predefined plans have been removed. Pricing is now fully dynamic 
 * and controlled by the Super Admin via /payment-management.
 * Company Admins configure their own system/server count on /payments.
 */
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function SelectPlanPage() {
  const navigate = useNavigate();

  useEffect(() => {
    navigate('/payments', { replace: true });
  }, [navigate]);

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: '#060e1a', color: '#60a5fa', fontSize: 14 }}>
      Redirecting to payments…
    </div>
  );
}
