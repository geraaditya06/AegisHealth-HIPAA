import axios from 'axios'

const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const api = axios.create({ baseURL: BASE })

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const register = (email, password) =>
  api.post('/api/auth/register', { email, password })

export const login = (email, password) =>
  api.post('/api/auth/login', { email, password })

export const googleLogin = credential =>
  api.post('/api/auth/google', { credential })

export const runScan = (url) =>
  api.post('/api/scan', { url })

export const getScanHistory = () =>
  api.get('/api/scan/history')

// ── Enterprise scan endpoints ───────────────────────────────────────────────
export const queueScan = (url, projectId) =>
  api.post('/api/scan/queue', { url, project_id: projectId ?? null })

export const listScans = (params = {}) =>
  api.get('/api/scan/list', { params })

export const getScan = (scanId, enrich = false) =>
  api.get(`/api/scan/${scanId}`, { params: enrich ? { enrich: true } : {} })

/**
 * Download a scan export (pdf | json | csv) as a file.
 */
export const exportScan = async (scanId, format) => {
  const res = await api.get(`/api/scan/${scanId}/export`, {
    params: { format }, responseType: 'blob',
  })
  triggerBlobDownload(res.data, `scan_${scanId}.${format}`)
}

/** Export ad-hoc tool findings (Docker/Dependency) as pdf | json | csv. */
export const exportToolResults = async (findings, target, format) => {
  const res = await api.post('/api/tools/export', { findings, target, format }, { responseType: 'blob' })
  triggerBlobDownload(res.data, `${target || 'tool'}.${format}`)
}

function triggerBlobDownload(data, filename) {
  const url = window.URL.createObjectURL(new Blob([data]))
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', filename)
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

export const cancelScan = (scanId) =>
  api.post(`/api/scan/${scanId}/cancel`)

/** Lightweight progress snapshot used by the WebSocket polling fallback. */
export const getScanStatus = (scanId) =>
  api.get(`/api/scan/${scanId}/status`)

export const retryScan = (scanId) =>
  api.post(`/api/scan/${scanId}/retry`)

// ── Dashboard & notifications ───────────────────────────────────────────────
export const getDashboard = () =>
  api.get('/api/dashboard')

export const getNotifications = (params = {}) =>
  api.get('/api/notifications', { params })

export const getUnreadCount = () =>
  api.get('/api/notifications/unread-count')

export const markNotificationRead = (id) =>
  api.post(`/api/notifications/${id}/read`)

export const markAllNotificationsRead = () =>
  api.post('/api/notifications/read-all')

export const logout = () =>
  api.post('/api/auth/logout')

// ── Security tools (Docker + Dependency scanners) ───────────────────────────
export const scanDocker = (image, dockerfile) =>
  api.post('/api/tools/docker', { image: image || null, dockerfile: dockerfile || null })

export const scanDependencies = (requirements, packageJson) =>
  api.post('/api/tools/dependencies', { requirements: requirements || null, package_json: packageJson || null })

/**
 * Open a WebSocket to stream live progress for a scan.
 * The JWT is passed as a query param because browsers cannot set headers on
 * the WebSocket handshake. Returns the WebSocket instance (caller closes it).
 */
export const openScanSocket = (scanId) => {
  const token = localStorage.getItem('token') || ''
  const wsBase = BASE.replace(/^http/, 'ws')
  return new WebSocket(`${wsBase}/api/scan/ws/${scanId}?token=${encodeURIComponent(token)}`)
}

export const triggerDeploy = (repo_url, branch) =>
  api.post('/api/deploy', { repo_url, branch })

export const getDeployHistory = () =>
  api.get('/api/deploy/history')

export const getAuditLogs = () =>
  api.get('/api/audit')

export const generateReport = (findings, url) =>
  api.post('/api/scan/generate-report', { findings, url }, {
    responseType: 'blob',
  })

export const downloadReport = async (reportPath) => {
  const res = await api.get('/api/scan/report/download', {
    params: { file: reportPath },
    responseType: 'blob',
  })
  // Create a download link and trigger it
  const blob = new Blob([res.data], { type: 'application/pdf' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', reportPath.split(/[/\\]/).pop() || 'report.pdf')
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

export default api
