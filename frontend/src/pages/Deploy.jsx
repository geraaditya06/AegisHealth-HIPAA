import { useState, useEffect } from 'react'
import { triggerDeploy, getDeployHistory } from '../api'

export default function Deploy() {
  const [repo, setRepo] = useState('')
  const [branch, setBranch] = useState('main')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    getDeployHistory().then(r => setHistory(r.data.deployments || [])).catch(() => {})
  }, [])

  async function handleDeploy(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const res = await triggerDeploy(repo, branch)
      setResult(res.data)
      setHistory(h => [res.data, ...h])
    } catch (err) {
      setError(err.response?.data?.detail || 'Deployment failed')
    }
    setLoading(false)
  }

  const statusColor = s => s === 'passed' ? '#22c55e' : s === 'failed' ? '#ef4444' : '#f59e0b'

  return (
    <div className="page-shell">
      <section className="hero-panel deploy-hero">
        <div className="hero-copy">
          <span className="page-kicker">Secure Release Gate</span>
          <h1 className="page-title">Prevent unsafe healthcare code from reaching production.</h1>
          <p className="page-subtitle">Run deployment checks inside the same visual language as the scanner and lock release decisions to compliance posture.</p>
        </div>
        <div className="hero-stat-grid">
          <div className="hero-stat-card">
            <span>Gate Status</span>
            <strong>HIPAA-aware deploy review</strong>
          </div>
          <div className="hero-stat-card">
            <span>History</span>
            <strong>{history.length} recorded attempts</strong>
          </div>
        </div>
      </section>

      <div className="page-grid">
        <form onSubmit={handleDeploy} className="glass-card form-card">
          <div className="section-header">
            <div>
              <div className="section-title">Launch Review</div>
              <div className="section-subtitle">Submit a repo and branch to test before deployment</div>
            </div>
          </div>
          <input
            placeholder="GitHub repo URL (https://github.com/...)"
            value={repo} onChange={e => setRepo(e.target.value)} required
            className="control-input"
          />
          <input
            placeholder="Branch (e.g. main, dev)"
            value={branch} onChange={e => setBranch(e.target.value)}
            className="control-input"
          />
          {error && <div style={{ color: '#ff7373', fontSize: 12 }}>{error}</div>}
          <button type="submit" disabled={loading} className="primary-action">
            {loading ? 'Running HIPAA tests...' : '🚀 Deploy →'}
          </button>
        </form>

        <div className="glass-card stacked-rail">
          <div className="section-header">
            <div>
              <div className="section-title">Deployment Rules</div>
              <div className="section-subtitle">A quick reminder of the current release posture</div>
            </div>
          </div>
          <div className="metric-stack">
            <div className="metric-card">
              <span>Blocking Rule</span>
              <strong>Critical HIPAA failures stop release</strong>
            </div>
            <div className="metric-card">
              <span>Team Mode</span>
              <strong>Review before push to production</strong>
            </div>
            <div className="metric-card">
              <span>Suggested Flow</span>
              <strong>Scan, remediate, then deploy</strong>
            </div>
          </div>
        </div>
      </div>

      {result && (
        <div className="glass-card" style={{ borderColor: `${statusColor(result.status)}50` }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: statusColor(result.status), marginBottom: 8 }}>
            {result.status === 'passed' ? '✓ Deployment Successful' : '✗ Deployment Blocked'}
          </div>
          {result.deploy_url && (
            <div className="data-url">Live at: {result.deploy_url}</div>
          )}
          {result.failed_checks && result.failed_checks.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="section-subtitle" style={{ marginBottom: 8 }}>Failed checks</div>
              {result.failed_checks.map((c, i) => (
                <div key={i} style={{ fontSize: 11, color: '#ff8080', padding: '4px 0' }}>
                  ✗ {c.check_id} — {c.description}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="glass-card">
        <div className="section-header">
          <div>
            <div className="section-title">Deployment History</div>
            <div className="section-subtitle">Every launch request captured in the same visual timeline</div>
          </div>
        </div>
        {history.length === 0 ? (
          <div className="empty-state">No deployments yet.</div>
        ) : history.map((d, i) => (
          <div key={i} className="timeline-row">
            <div className="timeline-icon" style={{ color: statusColor(d.status), background: `${statusColor(d.status)}18` }}>
              {d.status === 'passed' ? '✓' : d.status === 'failed' ? '✗' : '⟳'}
            </div>
            <div className="timeline-content">
              <div className="timeline-title">{d.repo_url}</div>
              <div className="timeline-subtitle">{d.branch}</div>
            </div>
            <div style={{ fontSize: 10, fontWeight: 700, color: statusColor(d.status) }}>
              {d.status?.toUpperCase()}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
