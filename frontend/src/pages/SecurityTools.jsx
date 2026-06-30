/**
 * SecurityTools — Docker image / Dockerfile scanner + Dependency CVE scanner.
 *
 * Two standalone tools that POST to /api/tools/docker and /api/tools/dependencies.
 * Both return the same { score, rating, score_breakdown, severity_counts,
 * findings, summary } shape as URL scans, so results reuse CategoryScores and
 * the existing finding visual language. Matches the dark cockpit design.
 */
import { useState } from 'react'
import { scanDocker, scanDependencies, exportToolResults } from '../api'
import CategoryScores from '../components/CategoryScores'
import FindingCard from '../components/FindingCard'
import ExecutiveRisk from '../components/ExecutiveRisk'
import ExportButtons from '../components/ExportButtons'

const scoreColor = s => s >= 85 ? '#22c55e' : s >= 60 ? '#f59e0b' : '#ef4444'

function ResultView({ result }) {
  if (!result) return null
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="glass-card result-overview">
        <div className="score-orb">
          <div style={{ fontSize: 48, fontWeight: 700, color: scoreColor(result.score), lineHeight: 1 }}>{result.score}</div>
          <div className="score-caption">out of 100</div>
        </div>
        <div className="result-copy">
          <div className="table-pill" style={{ color: scoreColor(result.score), background: `${scoreColor(result.score)}18`, display: 'inline-flex', marginBottom: 8 }}>{result.rating}</div>
          <div className="data-url">{result.target}</div>
          {result.summary && Object.keys(result.summary).length > 0 && (
            <div className="data-muted" style={{ marginTop: 8 }}>
              {Object.entries(result.summary).map(([k, v]) => (
                <span key={k} style={{ marginRight: 14 }}>{k}: <strong>{Array.isArray(v) ? v.join(', ') : v}</strong></span>
              ))}
            </div>
          )}
          <div style={{ marginTop: 12 }}>
            <ExportButtons onExport={(fmt) => exportToolResults(result.findings, result.target, fmt)} />
          </div>
        </div>
      </div>

      {result.score_breakdown?.categories && <CategoryScores breakdown={result.score_breakdown} />}

      {result.risk_analysis && <ExecutiveRisk analysis={result.risk_analysis} />}

      <div className="glass-card">
        <div className="section-header">
          <div><div className="section-title">Findings</div><div className="section-subtitle">{result.findings.length} checks</div></div>
        </div>
        <div className="findings-stack">
          {result.findings.map((f, i) => <FindingCard key={i} finding={f} />)}
        </div>
      </div>
    </div>
  )
}

export default function SecurityTools() {
  const [tab, setTab] = useState('docker')

  // Docker tab state
  const [image, setImage] = useState('')
  const [dockerfile, setDockerfile] = useState('')
  const [dockerLoading, setDockerLoading] = useState(false)
  const [dockerResult, setDockerResult] = useState(null)

  // Dependency tab state
  const [requirements, setRequirements] = useState('')
  const [packageJson, setPackageJson] = useState('')
  const [depLoading, setDepLoading] = useState(false)
  const [depResult, setDepResult] = useState(null)

  const [error, setError] = useState('')

  async function runDocker() {
    setError(''); setDockerLoading(true); setDockerResult(null)
    try {
      const res = await scanDocker(image.trim(), dockerfile)
      setDockerResult(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Docker scan failed.')
    }
    setDockerLoading(false)
  }

  async function runDeps() {
    setError(''); setDepLoading(true); setDepResult(null)
    try {
      const res = await scanDependencies(requirements, packageJson)
      setDepResult(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Dependency scan failed.')
    }
    setDepLoading(false)
  }

  const tabBtn = (id, label) => (
    <button
      onClick={() => setTab(id)}
      className="secondary-action"
      style={{
        background: tab === id ? 'linear-gradient(135deg,#0ea5e9,#2563eb)' : undefined,
        color: tab === id ? '#fff' : undefined,
        borderColor: tab === id ? 'transparent' : undefined,
      }}
    >{label}</button>
  )

  return (
    <div className="page-shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="page-kicker">Security Tools</span>
          <h1 className="page-title">Scan containers and dependencies for supply-chain risk.</h1>
          <p className="page-subtitle">Static Docker/Dockerfile hardening checks and dependency CVE scanning (OSV.dev) — scored in the same compliance system.</p>
        </div>
        <div className="hero-stat-grid">
          <div className="hero-stat-card"><span>Docker</span><strong>Image & Dockerfile audit</strong></div>
          <div className="hero-stat-card"><span>Dependencies</span><strong>CVE + outdated detection</strong></div>
        </div>
      </section>

      <div className="glass-card" style={{ display: 'flex', gap: 10 }}>
        {tabBtn('docker', '🐳 Docker Scanner')}
        {tabBtn('deps', '📦 Dependency Scanner')}
      </div>

      {error && (
        <div className="glass-card" style={{ borderColor: 'rgba(239,68,68,0.28)', color: '#ff7b7b' }}>{error}</div>
      )}

      {tab === 'docker' && (
        <div className="glass-card">
          <div className="section-header"><div><div className="section-title">Docker Scanner</div><div className="section-subtitle">Provide an image reference and/or paste a Dockerfile</div></div></div>
          <input
            className="scan-box-input" style={{ width: '100%', marginBottom: 10 }}
            placeholder="Image reference (optional) e.g. python:3.12-slim"
            value={image} onChange={e => setImage(e.target.value)}
          />
          <textarea
            className="scan-box-input"
            style={{ width: '100%', minHeight: 180, fontFamily: '"IBM Plex Mono", monospace', resize: 'vertical' }}
            placeholder={'Paste Dockerfile content here…\n\nFROM python:3.12-slim\nRUN pip install flask==3.0.0\nUSER appuser\nCMD ["python","app.py"]'}
            value={dockerfile} onChange={e => setDockerfile(e.target.value)}
          />
          <button onClick={runDocker} disabled={dockerLoading} className="dash-hero-cta" style={{ marginTop: 12 }}>
            {dockerLoading ? 'Scanning…' : 'Scan Docker →'}
          </button>
          <div style={{ marginTop: 18 }}><ResultView result={dockerResult} /></div>
        </div>
      )}

      {tab === 'deps' && (
        <div className="glass-card">
          <div className="section-header"><div><div className="section-title">Dependency Scanner</div><div className="section-subtitle">Paste requirements.txt and/or package.json</div></div></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 6 }}>requirements.txt</div>
              <textarea
                className="scan-box-input"
                style={{ width: '100%', minHeight: 180, fontFamily: '"IBM Plex Mono", monospace', resize: 'vertical' }}
                placeholder={'flask==2.0.1\nrequests==2.25.0\ndjango>=3.2'}
                value={requirements} onChange={e => setRequirements(e.target.value)}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 6 }}>package.json</div>
              <textarea
                className="scan-box-input"
                style={{ width: '100%', minHeight: 180, fontFamily: '"IBM Plex Mono", monospace', resize: 'vertical' }}
                placeholder={'{\n  "dependencies": {\n    "lodash": "4.17.11"\n  }\n}'}
                value={packageJson} onChange={e => setPackageJson(e.target.value)}
              />
            </div>
          </div>
          <button onClick={runDeps} disabled={depLoading} className="dash-hero-cta" style={{ marginTop: 12 }}>
            {depLoading ? 'Scanning…' : 'Scan Dependencies →'}
          </button>
          <div style={{ marginTop: 18 }}><ResultView result={depResult} /></div>
        </div>
      )}
    </div>
  )
}
