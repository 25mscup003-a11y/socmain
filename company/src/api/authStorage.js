// Support logins live in this tab; the original account stays in localStorage.
const url = new URL(window.location.href);
export const incomingImpersonationToken = new URLSearchParams(url.hash.slice(1)).get('impersonationToken')
  || url.searchParams.get('impersonationToken');
const marker = 'co_support_session';
if (incomingImpersonationToken) {
  sessionStorage.setItem(marker, 'true');
  ['co_token', 'co_user', 'co_company', 'co_tenant', 'co_impersonation', 'partner_plan']
    .forEach(key => sessionStorage.removeItem(key));
  sessionStorage.setItem('co_token', incomingImpersonationToken);
  sessionStorage.setItem('co_impersonation', JSON.stringify({ active: true }));
  url.searchParams.delete('impersonationToken');
  url.searchParams.delete('impersonation');
  const fragment = new URLSearchParams(url.hash.slice(1));
  if (fragment.has('impersonationToken')) {
    fragment.delete('impersonationToken');
    url.hash = fragment.toString();
  }
  window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash);
}
// Keep the marker after logout, so this tab cannot fall back to the original account.
export const authStorage = sessionStorage.getItem(marker) === 'true' ? sessionStorage : localStorage;
