import { useEffect, useState } from 'react'
import { getAuditLogs } from '../api'

export default function AuditLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAuditLogs().then(r => {
      setLogs(r.data.logs || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const tagColor = action => {
    if (action === 'login' || action === 'register' || action === 'google_login') return '#8b5cf6'
    if (action === 'scan') return '#0ea5e9'
    if (action === 'deploy') return '#22c55e'
    return '#f59e0b'
  }

  return (
    <div className="page-shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="page-kicker">Forensic Timeline</span>
          <h1 className="page-title">Every important operator action captured in a unified audit stream.</h1>
          <p className="page-subtitle">A synchronized command-center view for evidence trails, login events, and security workflow activity.</p>
        </div>
        <div className="hero-stat-grid">
          <div className="hero-stat-card">
            <span>Total Events</span>
            <strong>{logs.length}</strong>
          </div>
          <div className="hero-stat-card">
            <span>Audit Mode</span>
            <strong>Chronological evidence</strong>
          </div>
        </div>
      </section>

      <div className="glass-card">
        <div className="section-header">
          <div>
            <div className="section-title">Audit Logs</div>
            <div className="section-subtitle">Every action recorded to support healthcare-grade traceability</div>
          </div>
        </div>
        {loading ? (
          <div className="empty-state">Loading logs...</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">No activity yet.</div>
        ) : logs.map((log, i) => (
          <div key={i} className="timeline-row">
            <div className="timeline-time">
              {new Date(log.created_at).toLocaleTimeString()}
            </div>
            <span className="table-pill" style={{
              color: tagColor(log.action),
              background: `${tagColor(log.action)}18`,
              border: `1px solid ${tagColor(log.action)}40`
            }}>{log.action?.toUpperCase()}</span>
            <div className="timeline-content">
              <div className="timeline-title">{log.resource}</div>
              <div className="timeline-subtitle">IP: {log.ip_address}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
