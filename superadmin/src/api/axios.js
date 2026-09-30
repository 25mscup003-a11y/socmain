import axios from 'axios';
import { API_BASE_URL } from './config';

const api = axios.create({
  baseURL: API_BASE_URL,
  // No withCredentials — we use Authorization header (JWT), not cookies
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sa_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  const activeCompanyId = localStorage.getItem('sa_active_company_id');
  if (activeCompanyId) config.headers['x-company-id'] = activeCompanyId;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sa_token');
      localStorage.removeItem('sa_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default api;
