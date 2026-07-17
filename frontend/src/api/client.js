import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
});

// Inject Bearer token on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinelx_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 — redirect to login
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('sentinelx_token');
      localStorage.removeItem('sentinelx_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ─────────────── Auth ────────────────────────────────────────────────────────
export const authAPI = {
  login: (data)         => api.post('/auth/login', data),
  me:    ()             => api.get('/auth/me'),
  refresh: (token)      => api.post('/auth/refresh', { refresh_token: token }),
  changePassword: (data)=> api.post('/auth/change-password', data),
  setupMFA: ()          => api.post('/auth/mfa/setup'),
  verifyMFA: (code)     => api.post('/auth/mfa/verify', { totp_code: code }),
};

// ─────────────── Dashboard ───────────────────────────────────────────────────
export const dashboardAPI = {
  getStats:    ()         => api.get('/dashboard/stats'),
  getTimeline: (days = 7) => api.get(`/dashboard/timeline?days=${days}`),
};

// ─────────────── Alerts ──────────────────────────────────────────────────────
export const alertsAPI = {
  list:        (params)      => api.get('/alerts', { params }),
  get:         (id)          => api.get(`/alerts/${id}`),
  update:      (id, data)    => api.patch(`/alerts/${id}`, data),
  delete:      (id)          => api.delete(`/alerts/${id}`),
  acknowledge: (id)          => api.post(`/alerts/${id}/acknowledge`),
  summary:     ()            => api.get('/alerts/stats/summary'),
};

// ─────────────── Incidents ───────────────────────────────────────────────────
export const incidentsAPI = {
  list:       (params)       => api.get('/incidents', { params }),
  create:     (data)         => api.post('/incidents', data),
  get:        (id)           => api.get(`/incidents/${id}`),
  update:     (id, data)     => api.patch(`/incidents/${id}`, data),
  addComment: (id, content)  => api.post(`/incidents/${id}/comments`, { content }),
  getComments:(id)           => api.get(`/incidents/${id}/comments`),
  linkAlert:  (incId, alId)  => api.post(`/incidents/${incId}/link-alert/${alId}`),
};

// ─────────────── Assets ──────────────────────────────────────────────────────
export const assetsAPI = {
  list:   (params)     => api.get('/assets', { params }),
  create: (data)       => api.post('/assets', data),
  get:    (id)         => api.get(`/assets/${id}`),
  update: (id, data)   => api.patch(`/assets/${id}`, data),
  delete: (id)         => api.delete(`/assets/${id}`),
  topology: ()         => api.get('/assets/topology'),
};

// ─────────────── Logs ────────────────────────────────────────────────────────
export const logsAPI = {
  list:   (params) => api.get('/logs', { params }),
  ingest: (data)   => api.post('/logs/ingest', data),
};

// ─────────────── Rules ───────────────────────────────────────────────────────
export const rulesAPI = {
  list:   (params)      => api.get('/rules', { params }),
  create: (data)        => api.post('/rules', data),
  get:    (id)          => api.get(`/rules/${id}`),
  update: (id, data)    => api.patch(`/rules/${id}`, data),
  delete: (id)          => api.delete(`/rules/${id}`),
  toggle: (id)          => api.post(`/rules/${id}/toggle`),
  stats:  ()            => api.get('/rules/stats'),
  mitreMatrix: ()       => api.get('/rules/mitre/matrix'),
};

// ─────────────── SOAR ────────────────────────────────────────────────────────
export const soarAPI = {
  listPlaybooks:  ()            => api.get('/soar/playbooks'),
  runPlaybook:    (id, data)    => api.post(`/soar/playbooks/${id}/run`, data),
  listExecutions: (limit = 50)  => api.get(`/soar/executions?limit=${limit}`),
};

// ─────────────── Threat Intel ────────────────────────────────────────────────
export const threatIntelAPI = {
  listFeeds:   (params)   => api.get('/threat-intel/feeds', { params }),
  feedStats:   ()         => api.get('/threat-intel/feeds/stats'),
  enrichIP:    (ip)       => api.post(`/threat-intel/enrich/ip/${ip}`),
  enrichHash:  (hash)     => api.post(`/threat-intel/enrich/hash/${hash}`),
  enrichDomain:(domain)   => api.post(`/threat-intel/enrich/domain/${domain}`),
};

// ─────────────── Threat Hunting ──────────────────────────────────────────────
export const huntAPI = {
  search:       (params) => api.get('/hunt/search', { params }),
  savedSearches:()       => api.get('/hunt/saved-searches'),
};

// ─────────────── Vulnerabilities ─────────────────────────────────────────────
export const vulnsAPI = {
  list:   (params)      => api.get('/vulnerabilities', { params }),
  create: (data)        => api.post('/vulnerabilities', data),
  get:    (id)          => api.get(`/vulnerabilities/${id}`),
  update: (id, data)    => api.patch(`/vulnerabilities/${id}`, data),
  stats:  ()            => api.get('/vulnerabilities/stats'),
};

// ─────────────── Reports ─────────────────────────────────────────────────────
export const reportsAPI = {
  list:       ()      => api.get('/reports'),
  generate:   (data)  => api.post('/reports/generate', data),
  templates:  ()      => api.get('/reports/templates'),
};

// ─────────────── Admin ───────────────────────────────────────────────────────
export const adminAPI = {
  listUsers:      ()           => api.get('/admin/users'),
  updateRole:     (id, role)   => api.patch(`/admin/users/${id}/role?role=${role}`),
  toggleUser:     (id)         => api.patch(`/admin/users/${id}/toggle-active`),
  listRules:      ()           => api.get('/admin/rules'),
  systemStats:    ()           => api.get('/admin/system-stats'),
  auditLogs:      (params)     => api.get('/admin/audit-logs', { params }),
};

export default api;
