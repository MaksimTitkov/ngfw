import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

// ---- Rules ----
export const rulesApi = {
  getFolderTree: (params) => api.get('/rules/folders/tree', { params }),
  create: (data) => api.post('/rules/create', data),
  update: (data) => api.post('/rules/update', data),
  delete: (data) => api.post('/rules/delete', data),
  toggle: (data) => api.post('/rules/toggle', data),
  reorder: (data) => api.post('/rules/reorder', data),
  bulkToggle: (data) => api.post('/rules/bulk_toggle', data),
  bulkAction: (data) => api.post('/rules/bulk_action', data),
  transfer: (data) => api.post('/rules/transfer', data),
  acknowledge: (data) => api.post('/rules/acknowledge', data),
}

// ---- Objects ----
export const objectsApi = {
  list: (params) => api.get('/objects/list', { params }),
  resolve: (params) => api.get('/object/resolve', { params }),
  usage: (params) => api.get('/object/usage', { params }),
  create: (data) => api.post('/objects/create', data),
  update: (data) => api.post('/objects/update', data),
  delete: (data) => api.post('/objects/delete', data),
  replaceInRules: (data) => api.post('/objects/replace-in-rules', data),
}

// ---- NAT ----
export const natApi = {
  getFolderTree: (params) => api.get('/nat/folders/tree', { params }),
  createRule: (data) => api.post('/nat/rules/create', data),
  updateRule: (data) => api.post('/nat/rules/update', data),
  deleteRule: (data) => api.post('/nat/rules/delete', data),
  toggleRule: (data) => api.post('/nat/rules/toggle', data),
  reorderRules: (data) => api.post('/nat/rules/reorder', data),
}

// ---- Logs ----
export const logsApi = {
  fetch: (data) => api.post('/logs/fetch', data),
  query: (data) => api.post('/logs/query', data),
  status: () => api.get('/logs/status'),
  clear: (data) => api.post('/logs/clear', data),
  export: (params) => api.get('/logs/export', { params }),
  topStats: (params) => api.get('/logs/top_stats', { params }),
  ruleStats: (params) => api.get('/logs/rule_stats', { params }),
}

// ---- Analyzer ----
export const analyzerApi = {
  run: (data) => api.post('/analyzer/run', data),
  cached: (params) => api.get('/analyzer/cached', { params }),
}

// ---- System ----
export const systemApi = {
  getAdmins: () => api.get('/system/admins'),
  createAdmin: (data) => api.post('/system/admins/create', data),
  adminAction: (data) => api.post('/system/admins/action', data),
  changePassword: (data) => api.post('/system/admins/password', data),
  getBackups: () => api.get('/system/backups'),
  createBackup: (data) => api.post('/system/backups/create', data),
  deleteBackup: (data) => api.post('/system/backups/delete', data),
  getInterfaces: () => api.get('/system/interfaces'),
  getRouting: () => api.get('/system/routing'),
  createRoute: (data) => api.post('/system/routing/create', data),
  deleteRoute: (data) => api.post('/system/routing/delete', data),
  getTimeouts: () => api.get('/system/timeouts'),
  setTimeouts: (data) => api.post('/system/timeouts/set', data),
}

// ---- Scheduler ----
export const schedulerApi = {
  list: () => api.get('/scheduler/tasks'),
  create: (data) => api.post('/scheduler/tasks', data),
  update: (id, data) => api.patch(`/scheduler/tasks/${id}`, data),
  delete: (id) => api.delete(`/scheduler/tasks/${id}`),
  run: (id) => api.post(`/scheduler/tasks/${id}/run`),
}

// ---- Diff ----
export const diffApi = {
  compare: (data) => api.post('/diff/devices', data),
  modified: (params) => api.get('/diff/modified', { params }),
}

// ---- Changelog ----
export const changelogApi = {
  query: (data) => api.post('/changelog/query', data),
}

// ---- Search ----
export const searchApi = {
  search: (data) => api.post('/search', data),
}

// ---- Templates ----
export const templatesApi = {
  save: (data) => api.post('/templates/save', data),
  apply: (data) => api.post('/templates/apply', data),
  delete: (data) => api.post('/templates/delete', data),
  profiles: () => api.get('/profiles/list'),
}

// ---- Top-level actions (non-API routes) ----
export const deviceApi = {
  sync: (device_id) => axios.post(device_id ? `/sync?device_id=${encodeURIComponent(device_id)}` : '/sync'),
  commit: (data) => axios.post('/commit', data),
}
