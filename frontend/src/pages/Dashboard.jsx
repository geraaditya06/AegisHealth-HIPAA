import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getDashboard, getScanHistory } from '../api'
import { onScanUpdate } from '../lib/scanEvents'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie,
} from 'recharts'

/* ────────── tiny animated counter ────────── */
function AnimatedNumber({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    if (!value && value !== 0) return
    const target = typeof value === 'number' ? value : parseInt(value, 10) || 0
    const start = performance.now()
    const step = ts => {
      const progress = Math.min((ts - start) / duration, 1)
      const ease = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(target * ease))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [value, duration])
  return <>{display}</>
}

/* ────────── SVG score gauge ring ────────── */
function ScoreGauge({ score, size = 180 }) {
  const r = (size - 20) / 2
  const circ = 2 * Math.PI * r
  const pct = Math.min(score, 100) / 100
  const offset = circ * (1 - pct)
  const color = score >= 85 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444'
  return (
    <div className="dash-gauge">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <filter id="glow-gauge"><feGaussianBlur stdDeviation="4" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor={color} /><stop offset="100%" stopColor="#38bdf8" /></linearGradient>
        </defs>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(125,211,252,0.06)" strokeWidth="8" />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="url(#gaugeGrad)" strokeWidth="8" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset} transform={`rotate(-90 ${size/2} ${size/2})`} filter="url(#glow-gauge)" className="dash-gauge-ring" />
      </svg>
      <div className="dash-gauge-value" style={{ color }}>
        <AnimatedNumber value={score} /><span className="dash-gauge-label">/ 100</span>
      </div>
    </div>
  )
}

const SEVERITY_PIE_COLORS = { Critical: '#ef4444', Warning: '#f59e0b', Low: '#22c55e' }

/* ════════════ MAIN DASHBOARD ════════════ */
export default function Dashboard() {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [time, setTime] = useState(new Date())
  const [degraded, setDegraded] = useState(false)

  // Build a usable dashboard from the recent-scans list when the dedicated
  // /api/dashboard endpoint is unavailable (e.g. an older backend build).
  function buildFallbackDashboard(scanList) {
    const done = scanList.filter(s => s.score != null && ['complete', 'completed'].includes(s.status))
    const scores = done.map(s => s.score)
    const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0
    const todayStr = new Date().toDateString()
    return {
      cards: {
        compliance_score: avg,
        critical_findings: done.filter(s => s.score < 60).length,
        projects: 0,
        scans_today: scanList.filter(s => new Date(s.created_at).toDateString() === todayStr).length,
        average_risk: scores.length ? Math.max(0, 100 - avg) : 0,
      },
      charts: {
        compliance_trend: [...done].reverse().map(s => ({ score: s.score })),
        category_scores: [],
        severity_distribution: [],
        scan_timeline: [],
        top_vulnerabilities: [],
      },
      total_scans: done.length,
    }
  }

  // Single source of truth for (re)loading dashboard data.
  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    let scanList = []
    try {
      const r = await getScanHistory()
      scanList = r.data.scans || []
      setScans(scanList)
    } catch { /* keep previous */ }

    try {
      const d = await getDashboard()
      setData(d.data)
      setDegraded(false)
    } catch {
      // Dedicated dashboard endpoint missing/unreachable — fall back to a
      // summary computed from recent scans so the page still works.
      setData(buildFallbackDashboard(scanList))
      setDegraded(true)
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial load.
  useEffect(() => { load(true) }, [load])

  // Live synchronization: refresh automatically when a scan changes state,
  // when the window regains focus, and on a gentle interval — so charts and
  // cards never require a manual refresh.
  useEffect(() => {
    const unsub = onScanUpdate(() => load(false))
    const onFocus = () => load(false)
    window.addEventListener('focus', onFocus)
    const poll = setInterval(() => load(false), 20000)
    return () => { unsub(); window.removeEventListener('focus', onFocus); clearInterval(poll) }
  }, [load])

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const scoreColor = s => s >= 85 ? '#22c55e' : s >= 60 ? '#f59e0b' : '#ef4444'
  const scoreLabel = s => s >= 85 ? 'Compliant' : s >= 60 ? 'Needs Work' : 'Non-Compliant'

  const cards = data?.cards || { compliance_score: 0, critical_findings: 0, projects: 0, scans_today: 0, average_risk: 0 }
  const charts = data?.charts || {}
  const trend = (charts.compliance_trend || []).map((d, i) => ({ name: `#${i + 1}`, score: d.score }))
  const categoryScores = charts.category_scores || []
  const severityDist = charts.severity_distribution || []
  const timeline = (charts.scan_timeline || []).map(d => ({ name: (d.name || '').slice(5), value: d.value }))
  const topVulns = charts.top_vulnerabilities || []
  const avg = cards.compliance_score

  const statCards = [
    { icon: '🛡️', label: 'Compliance Score', value: cards.compliance_score, suffix: '/100', color: '#38bdf8' },
    { icon: '🚨', label: 'Critical Findings', value: cards.critical_findings, suffix: '', color: '#ef4444' },
    { icon: '🗂️', label: 'Projects', value: cards.projects, suffix: '', color: '#a78bfa' },
    { icon: '📅', label: 'Scans Today', value: cards.scans_today, suffix: '', color: '#22c55e' },
    { icon: '📉', label: 'Average Risk', value: cards.average_risk, suffix: '', color: '#f59e0b' },
  ]

  return (
    <div className="page-shell dash-shell">
      <div className="dash-bg-grid" />
      <div className="dash-bg-glow dash-bg-glow-1" />
      <div className="dash-bg-glow dash-bg-glow-2" />
      <div className="dash-bg-glow dash-bg-glow-3" />

      {degraded && (
        <div className="glass-card" style={{ borderColor: 'rgba(245,158,11,0.3)', color: '#f59e0b', fontSize: 12 }}>
          Showing a summary from recent scans. Live dashboard metrics are unavailable —
          restart the backend to enable full analytics (charts, category scores, top vulnerabilities).
        </div>
      )}

      {/* HERO */}
      <section className="dash-hero">
        <div className="dash-hero-content">
          <div className="dash-hero-kicker">
            <span className="dash-live-dot" />
            <span>Live Command Center</span>
            <span className="dash-hero-time">{time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
          </div>
          <h1 className="dash-hero-title">Your <span className="dash-gradient-text">Security Posture</span> at a Glance</h1>
          <p className="dash-hero-sub">Real-time HIPAA compliance monitoring, AI-powered risk assessment, and continuous security posture scoring — all in one living dashboard.</p>
          <button onClick={() => navigate('/scanner')} className="dash-hero-cta">Run New Scan →</button>
        </div>
        <div className="dash-hero-gauge">
          <ScoreGauge score={avg || 0} size={180} />
          <div className="dash-hero-gauge-label">
            <span>Compliance Score</span>
            <strong style={{ color: scoreColor(avg) }}>{scoreLabel(avg)}</strong>
          </div>
        </div>
      </section>

      {/* STAT CARDS ROW */}
      <div className="dash-stats-row">
        {statCards.map((stat, i) => (
          <div key={i} className="dash-stat-card" style={{ '--stat-color': stat.color, animationDelay: `${i * 0.1}s` }}>
            <div className="dash-stat-glow" style={{ background: `radial-gradient(circle, ${stat.color}15, transparent 70%)` }} />
            <div className="dash-stat-top"><span className="dash-stat-icon">{stat.icon}</span></div>
            <div className="dash-stat-value" style={{ color: stat.color }}>
              <AnimatedNumber value={stat.value} />{stat.suffix}
            </div>
            <div className="dash-stat-label">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* MAIN GRID: trend + category scores */}
      <div className="dash-main-grid">
        <div className="dash-card dash-card-chart">
          <div className="dash-card-header">
            <div>
              <div className="dash-card-title">Compliance Trend</div>
              <div className="dash-card-sub">{time.toLocaleDateString()} · AegisHealth telemetry</div>
            </div>
            <div className="dash-card-badge">Live</div>
          </div>
          {trend.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="dashGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#38bdf8" stopOpacity={0.35} /><stop offset="95%" stopColor="#38bdf8" stopOpacity={0} /></linearGradient>
                  <filter id="glow-line"><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
                </defs>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#4a7a9a' }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#4a7a9a' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'rgba(8,13,20,0.95)', border: '1px solid rgba(56,189,248,0.2)', borderRadius: 14, fontSize: 12 }} />
                <Area type="monotone" dataKey="score" stroke="#38bdf8" fill="url(#dashGrad)" strokeWidth={3} filter="url(#glow-line)" dot={{ r: 4, fill: '#38bdf8', stroke: '#080d14', strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="dash-empty"><div className="dash-empty-icon">📈</div><div>No scan data yet</div><div className="dash-empty-sub">Run your first scan to see the trend</div></div>
          )}
        </div>

        <div className="dash-card dash-card-bars">
          <div className="dash-card-header">
            <div>
              <div className="dash-card-title">Category Scores</div>
              <div className="dash-card-sub">Average per HIPAA domain</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={categoryScores} layout="vertical" margin={{ left: 8 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 9, fill: '#4a7a9a' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={92} tick={{ fontSize: 9, fill: '#7a9ab8' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'rgba(8,13,20,0.95)', border: '1px solid rgba(56,189,248,0.2)', borderRadius: 12, fontSize: 11 }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {categoryScores.map((entry, i) => (
                  <Cell key={i} fill={entry.value >= 85 ? '#22c55e' : entry.value >= 60 ? '#f59e0b' : '#ef4444'} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* SECOND GRID: severity distribution + scan timeline + top vulns */}
      <div className="dash-main-grid">
        <div className="dash-card">
          <div className="dash-card-header"><div><div className="dash-card-title">Severity Distribution</div><div className="dash-card-sub">Open failed findings</div></div></div>
          {severityDist.some(d => d.value > 0) ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityDist} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={3}>
                  {severityDist.map((entry, i) => <Cell key={i} fill={SEVERITY_PIE_COLORS[entry.name] || '#38bdf8'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'rgba(8,13,20,0.95)', border: '1px solid rgba(56,189,248,0.2)', borderRadius: 12, fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="dash-empty"><div className="dash-empty-icon">✅</div><div>No open findings</div></div>
          )}
          <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap', marginTop: 4 }}>
            {severityDist.map(d => (
              <span key={d.name} style={{ fontSize: 11, color: 'var(--text2)', display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: 2, background: SEVERITY_PIE_COLORS[d.name] }} />{d.name}: {d.value}
              </span>
            ))}
          </div>
        </div>

        <div className="dash-card">
          <div className="dash-card-header"><div><div className="dash-card-title">Scan Timeline</div><div className="dash-card-sub">Scans per day (14d)</div></div></div>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timeline}>
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#4a7a9a' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 9, fill: '#4a7a9a' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'rgba(8,13,20,0.95)', border: '1px solid rgba(56,189,248,0.2)', borderRadius: 12, fontSize: 11 }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]} fill="#38bdf8" fillOpacity={0.85} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="dash-empty"><div className="dash-empty-icon">🗓️</div><div>No recent scans</div></div>
          )}
        </div>
      </div>

      {/* TOP VULNERABILITIES */}
      <div className="dash-card">
        <div className="dash-card-header"><div><div className="dash-card-title">Top Vulnerabilities</div><div className="dash-card-sub">Most frequent failing checks</div></div></div>
        {topVulns.length === 0 ? (
          <div className="dash-empty"><div className="dash-empty-icon">🔒</div><div>No recurring vulnerabilities</div></div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
            {topVulns.map((v, i) => {
              const c = ['critical', 'high'].includes((v.severity || '').toLowerCase()) ? '#ef4444' : ['warning', 'medium'].includes((v.severity || '').toLowerCase()) ? '#f59e0b' : '#22c55e'
              const max = topVulns[0].count || 1
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span className="table-pill" style={{ color: c, background: `${c}18`, fontSize: 10, minWidth: 64, textAlign: 'center' }}>{v.check_id}</span>
                  <span style={{ fontSize: 12, color: 'var(--text2)', minWidth: 110 }}>{v.category}</span>
                  <div style={{ flex: 1, height: 8, borderRadius: 99, background: 'rgba(125,211,252,0.08)' }}>
                    <div style={{ width: `${(v.count / max) * 100}%`, height: '100%', borderRadius: 99, background: c, opacity: 0.85 }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: c, minWidth: 24, textAlign: 'right' }}>{v.count}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* RECENT SCANS TABLE */}
      <div className="dash-card dash-card-table">
        <div className="dash-card-header">
          <div><div className="dash-card-title">Recent Scans</div><div className="dash-card-sub">Last recorded URLs and posture snapshots</div></div>
          <button className="secondary-action" onClick={() => navigate('/history')}>View all →</button>
        </div>
        {loading ? (
          <div className="dash-empty"><div className="dash-loading-spinner" /><div>Loading scan data...</div></div>
        ) : scans.length === 0 ? (
          <div className="dash-empty">
            <div className="dash-empty-icon">🔍</div><div>No scans recorded yet</div>
            <button onClick={() => navigate('/scanner')} className="dash-empty-quicklink">Go to Scanner to run your first compliance check →</button>
          </div>
        ) : (
          <div className="dash-table-wrap">
            <table className="dash-table">
              <thead><tr>{['URL', 'Score', 'Rating', 'Date'].map(h => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {scans.map((s, idx) => (
                  <tr key={s.id} style={{ animationDelay: `${idx * 0.06}s`, cursor: 'pointer' }} onClick={() => navigate(`/history?scan=${s.id}`)}>
                    <td><span className="dash-table-url">{s.url}</span></td>
                    <td><span className="dash-table-score" style={{ color: scoreColor(s.score) }}>{s.score}</span></td>
                    <td><span className="dash-table-pill" style={{ color: scoreColor(s.score), background: `${scoreColor(s.score)}14`, borderColor: `${scoreColor(s.score)}30` }}>{scoreLabel(s.score)}</span></td>
                    <td className="dash-table-date">{new Date(s.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
