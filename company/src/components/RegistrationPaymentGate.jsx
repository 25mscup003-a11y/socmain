import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { registrationPaymentRedirect } from '../utils/registrationPayment';

export default function RegistrationPaymentGate({ children }) {
  const { user, company, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="loading">Loading…</div>;
  const destination = registrationPaymentRedirect(user, company, location);
  return destination ? <Navigate to={destination} replace /> : children;
}
