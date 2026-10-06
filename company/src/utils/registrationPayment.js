export function requiresRegistrationPayment(user, company) {
  return user?.role === 'company_admin' && company?.status === 'pending_payment';
}

export function registrationPaymentRedirect(user, company, location) {
  if (!requiresRegistrationPayment(user, company)) return null;
  const { pathname, search = '', state } = location;
  if (/^\/register(?:\/[^/]+)?\/?$/.test(pathname)) return null;
  if (['/login', '/forgot-password', '/reset-password'].includes(pathname)) return null;
  if (pathname === '/checkout' && ['base', 'enterprise'].includes(state?.checkout?.mode)) return null;
  return new URLSearchParams(search).get('tab') === 'enterprise'
    ? '/register?plan=enterprise' : '/register';
}
