import { useState, useEffect, useRef } from 'react'
import {
  queueScan, runScan, openScanSocket, getScan, getScanStatus, cancelScan,
  downloadReport, generateReport, exportScan,
} from '../api'
import CategoryScores from '../components/CategoryScores'
import FindingCard from '../components/FindingCard'
import ExecutiveRisk from '../components/ExecutiveRisk'
import ExportButtons from '../components/ExportButtons'
import { emitScanUpdate } from '../lib/scanEvents'

const TERMINAL = ['completed', 'complete', 'failed', 'cancelled']

// Maps backend pipeline phases to a friendly label + icon for the progress UI.
const PHASE_META = {
  queued: { icon: '🕐', text: 'Queued — waiting for an available worker…' },
  crawler: { icon: '🔍', text: 'Crawling target & discovering endpoints…' },
  scanner: { icon: '🛡️', text: 'Running HIPAA compliance checks…' },
  rule_engine: { icon: '📊', text: 'Scoring & rule engine analysis…' },
  report: { icon: '📄', text: 'Generating PDF compliance report…' },
  failed: { icon: '⚠️', text: 'Scan failed' },
  cancelled: { icon: '⏹️', text: 'Scan cancelled' },
}

export default function Scanner() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('queued')
  const [phaseMessage, setPhaseMessage] = useState('')
  const [eta, setEta] = useState(null)
  const [scanId, setScanId] = useState(null)
  const socketRef = useRef(null)
  const pollRef = useRef(null)
  const connectTimerRef = useRef(null)
  const finalizedRef = useRef(false)
  const wsConnectedRef = useRef(false)

  // Clean up all timers/sockets on unmount.
  useEffect(() => () => cleanup(), [])

  function cleanup() {
    if (socketRef.current) { try { socketRef.current.close() } catch { /* noop */ } socketRef.current = null }
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
    if (connectTimerRef.current) { clearTimeout(connectTimerRef.current); connectTimerRef.current = null }
  }

  function resetProgress() {
    setProgress(0); setPhase('queued'); setPhaseMessage(''); setEta(null)
  }

  function applyProgress(data) {
    if (data.progress != null) setProgress(data.progress)
    if (data.phase) setPhase(data.phase)
    if (data.phase_message) setPhaseMessage(data.phase_message)
    if (data.eta !== undefined) setEta(data.eta || null)
  }

  // Map a scan-detail (or synchronous scan) payload into the result UI shape.
  function normalizeResult(detail) {
    return {
      scan_id: detail.id ?? detail.scan_id,
      url: detail.url,
      score: detail.score,
      rating: detail.rating,
      findings: detail.findings || [],
      suggestions: detail.suggestions || [],
      risk_prediction: detail.risk_prediction,
      report_path: detail.report_path,
      // Detail stores the breakdown under category_scores; sync scan under score_breakdown.
      score_breakdown: detail.category_scores || detail.score_breakdown,
      severity_counts: detail.severity_counts,
      risk_analysis: detail.risk_analysis,
    }
  }

  // Fetch the full enriched result exactly once when a scan reaches terminal state.
  async function finalize(id) {
    if (finalizedRef.current) return
    finalizedRef.current = true
    cleanup()
    try {
      const detail = await getScan(id, true)
      setResult(normalizeResult(detail.data))
      setProgress(100)
    } catch {
      setError('Scan finished but the result could not be loaded.')
    }
    setLoading(false)
    // Notify the rest of the app (dashboard, history, charts) to refresh live.
    emitScanUpdate({ type: 'completed', scanId: id })
  }

  function handleTerminal(id, status, errMsg) {
    if (['completed', 'complete'].includes(status)) {
      finalize(id)
    } else if (status === 'failed') {
      cleanup(); setError(errMsg || 'Scan failed. Check the URL and try again.'); setLoading(false)
      emitScanUpdate({ type: 'failed', scanId: id })
    } else if (status === 'cancelled') {
      cleanup(); setError('Scan was cancelled.'); setLoading(false)
      emitScanUpdate({ type: 'cancelled', scanId: id })
    }
  }

  // Fallback channel: poll the lightweight status endpoint until terminal.
  function startPolling(id) {
    if (pollRef.current || finalizedRef.current) return
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getScanStatus(id)
        applyProgress(data)
        if (TERMINAL.includes(data.status)) handleTerminal(id, data.status, data.error)
      } catch { /* transient errors must not kill the poll loop */ }
    }, 1500)
  }

  // Preferred channel: WebSocket, with automatic fallback to polling.
  function connectWebSocket(id) {
    let socket
    try { socket = openScanSocket(id) } catch { startPolling(id); return }
    socketRef.current = socket
    wsConnectedRef.current = false

    // If the socket hasn't opened shortly, fall back to polling.
    connectTimerRef.current = setTimeout(() => {
      if (!wsConnectedRef.current && !finalizedRef.current) startPolling(id)
    }, 3000)

    socket.onopen = () => {
      wsConnectedRef.current = true
      if (connectTimerRef.current) { clearTimeout(connectTimerRef.current); connectTimerRef.current = null }
    }
    socket.onmessage = (evt) => {
      let data
      try { data = JSON.parse(evt.data) } catch { return }
      if (data.error) { startPolling(id); return }
      applyProgress(data)
      if (TERMINAL.includes(data.status)) handleTerminal(id, data.status, data.error)
    }
    socket.onerror = () => { if (!finalizedRef.current) startPolling(id) }
    socket.onclose = () => { if (!finalizedRef.current) startPolling(id) }
  }

  async function handleScan(e) {
    e.preventDefault()
    setLoading(true); setError(''); setResult(null); setShowSuggestions(false)
    resetProgress(); cleanup(); finalizedRef.current = false

    let id
    try {
      const res = await queueScan(url)        // 1) preferred: background queue
      id = res.data.scan_id
      setScanId(id)
      emitScanUpdate({ type: 'queued', scanId: id })
    } catch (err) {
      // The queue route is unavailable (e.g. an older backend build returns
      // 404). Fall back to the legacy synchronous scan so the scanner still
      // works end to end. (Restart the backend to enable the live queue/WS.)
      if (err?.response && err.response.status !== 404) {
        setError(err.response?.data?.detail || 'Could not start the scan. Try again.')
        setLoading(false)
        return
      }
      return runLegacyScan()
    }

    // 2) stream progress over WebSocket, 3) poll as a safety net.
    connectWebSocket(id)
    setTimeout(() => {
      if (!finalizedRef.current && !wsConnectedRef.current) startPolling(id)
    }, 3500)
  }

  // Compatibility path: the original synchronous endpoint returns the full
  // enriched result in one response (no queue/WebSocket required).
  async function runLegacyScan() {
    setPhase('scanner')
    setPhaseMessage('Running scan in compatibility mode…')
    setProgress(45)
    try {
      const res = await runScan(url)
      setResult(normalizeResult(res.data))
      setProgress(100)
      emitScanUpdate({ type: 'completed', scanId: res.data.scan_id })
    } catch (err) {
      setError(err.response?.data?.detail || 'Scan failed. Check the URL and try again.')
    }
    setLoading(false)
  }

  async function handleCancel() {
    if (scanId) { try { await cancelScan(scanId) } catch { /* ignore */ } }
    cleanup()
    finalizedRef.current = true
    setLoading(false)
    setError('Scan cancelled.')
  }

  async function handleDownload() {
    if (!result) return
    setDownloading(true)
    try {
      if (result.report_path) {
        await downloadReport(result.report_path)
      } else {
        const res = await generateReport(result.findings, result.url || url)
        const blob = new Blob([res.data], { type: 'application/pdf' })
        const blobUrl = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = blobUrl
        link.setAttribute('download', 'security_report.pdf')
        document.body.appendChild(link)
        link.click()
        link.remove()
        window.URL.revokeObjectURL(blobUrl)
      }
    } catch (err) {
      console.error('Download failed', err)
      alert('Failed to download report. Please try again.')
    }
    setDownloading(false)
  }

  const scoreColor = s => s >= 85 ? '#22c55e' : s >= 60 ? '#f59e0b' : '#ef4444'
  const meta = PHASE_META[phase] || PHASE_META.scanner
  const etaText = eta ? new Date(eta).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : null

  return (
    <div className="page-shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="page-kicker">Live Scanner</span>
          <h1 className="page-title">Scan websites inside the same animated AI security surface.</h1>
          <p className="page-subtitle">Background workers run the scan while WebSockets stream real crawler, scanner, rule-engine and report progress.</p>
        </div>
        <div className="hero-stat-grid">
          <div className="hero-stat-card">
            <span>Coverage</span>
            <strong>28 compliance checks</strong>
          </div>
          <div className="hero-stat-card">
            <span>AI Layer</span>
            <strong>Contextual remediation cards</strong>
          </div>

          <div className="scan-box-3d">
            <div className="scan-box-glow" />
            <div className="scan-box-glow scan-box-glow-b" />
            <div className="scan-box-ring scan-box-ring-1" />
            <div className="scan-box-ring scan-box-ring-2" />
            <div className="scan-box-inner">
              <div className="scan-box-header">
                <div className="scan-box-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                  </svg>
                </div>
                <div>
                  <div className="scan-box-label">Initiate Scan</div>
                  <div className="scan-box-sublabel">Deep HIPAA analysis</div>
                </div>
              </div>
              <form onSubmit={handleScan} className="scan-box-form">
                <input
                  type="text" placeholder="Paste target URL here..."
                  value={url} onChange={e => setUrl(e.target.value)} required
                  className="scan-box-input"
                />
                <button type="submit" disabled={loading} className="scan-box-btn">
                  <span className="scan-box-btn-bg" />
                  <span className="scan-box-btn-text">
                    {loading ? 'Scanning…' : 'Run Scan →'}
                  </span>
                </button>
              </form>
            </div>
            <div className="scan-box-particles">
              <span/><span/><span/><span/><span/><span/>
            </div>
          </div>
        </div>
      </section>

      {(loading || (progress > 0 && progress < 100)) && (
        <div className="glass-card" style={{ overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 18 }}>
            <div style={{
              width: 38, height: 38, borderRadius: 12,
              background: 'linear-gradient(135deg, #0ea5e9, #38bdf8)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 24px rgba(14,165,233,0.35)', fontSize: 18,
            }}>
              {meta.icon}
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: '#e0f2fe', letterSpacing: 0.2 }}>
                {phase === 'queued' ? 'Queued' : 'Scanning Target'}
              </div>
              <div style={{ fontSize: 11, color: '#7497b8', marginTop: 2 }}>
                {Math.round(progress)}% · {phaseMessage || meta.text}
                {etaText ? ` · ETA ${etaText}` : ''}
              </div>
            </div>
            <button onClick={handleCancel} type="button" className="secondary-action" style={{ marginLeft: 'auto' }}>
              Cancel
            </button>
            <div style={{
              fontSize: 20, fontWeight: 800, fontFamily: '"IBM Plex Mono", monospace',
              color: '#38bdf8', minWidth: 52, textAlign: 'right',
            }}>
              {Math.round(progress)}%
            </div>
          </div>

          <div style={{ position: 'relative', height: 6, borderRadius: 99, background: 'rgba(125, 211, 252, 0.08)', overflow: 'hidden' }}>
            <div style={{
              position: 'absolute', inset: '0 auto 0 0', width: `${progress}%`, borderRadius: 99,
              background: 'linear-gradient(90deg, #0ea5e9, #38bdf8, #7dd3fc)',
              boxShadow: '0 0 16px rgba(56,189,248,0.45)', transition: 'width 0.3s ease-out',
            }} />
          </div>

          {/* Phase steps */}
          <div style={{ display: 'flex', gap: 16, marginTop: 16, flexWrap: 'wrap' }}>
            {['crawler', 'scanner', 'rule_engine', 'report'].map((p) => {
              const order = ['crawler', 'scanner', 'rule_engine', 'report']
              const curIdx = order.indexOf(phase)
              const pIdx = order.indexOf(p)
              const isCurrent = p === phase
              const isPast = curIdx > pIdx
              return (
                <div key={p} style={{
                  display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
                  color: isCurrent ? '#e0f2fe' : isPast ? '#4ade80' : '#3d5a78',
                  fontWeight: isCurrent ? 600 : 400, transition: 'all 0.4s ease',
                  opacity: isCurrent ? 1 : isPast ? 0.7 : 0.4,
                }}>
                  <span style={{ fontSize: 13 }}>{isPast ? '✓' : PHASE_META[p].icon}</span>
                  {PHASE_META[p].text.replace('…', '')}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {error && (
        <div className="glass-card" style={{ borderColor: 'rgba(239,68,68,0.28)', color: '#ff7b7b' }}>
          {error}
        </div>
      )}

      {result && (
        <div className="page-shell" style={{ paddingTop: 0 }}>
          <div className="glass-card result-overview">
            <div className="score-orb">
              <div style={{ fontSize: 52, fontWeight: 700, color: scoreColor(result.score), lineHeight: 1 }}>
                {result.score}
              </div>
              <div className="score-caption">out of 100</div>
            </div>
            <div className="result-copy">
              <div className="table-pill" style={{ color: scoreColor(result.score), background: `${scoreColor(result.score)}18`, display: 'inline-flex', marginBottom: 8 }}>{result.rating}</div>
              <div className="data-url">{result.url}</div>
              <div className="data-muted" style={{ marginTop: 8 }}>
                {result.findings.filter(f => !f.passed && f.severity === 'critical').length} critical ·{' '}
                {result.findings.filter(f => !f.passed && f.severity === 'warning').length} warnings ·{' '}
                {result.findings.filter(f => f.passed).length} passed
              </div>
              <button onClick={handleDownload} disabled={downloading} style={{
                marginTop: 16, padding: '10px 24px',
                background: 'linear-gradient(135deg, #0ea5e9, #2563eb)', color: '#fff',
                border: 'none', borderRadius: 10, fontSize: 13, fontWeight: 700,
                cursor: downloading ? 'wait' : 'pointer', display: 'inline-flex',
                alignItems: 'center', gap: 8, letterSpacing: 0.3,
                boxShadow: '0 4px 20px rgba(14,165,233,0.35)', opacity: downloading ? 0.7 : 1,
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                  <polyline points="7 10 12 15 17 10"/>
                  <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                {downloading ? 'Downloading…' : 'Download PDF Report'}
              </button>
              <div style={{ marginTop: 14 }}>
                <ExportButtons onExport={(fmt) => exportScan(result.scan_id, fmt)} label="Export report" />
              </div>
            </div>
          </div>

          {/* Multi-category compliance scores */}
          {result.score_breakdown?.categories && (
            <CategoryScores breakdown={result.score_breakdown} />
          )}

          {/* Executive risk analysis */}
          {result.risk_analysis && <ExecutiveRisk analysis={result.risk_analysis} />}

          {result.suggestions?.length > 0 && (
            <div className="glass-card ai-suggestion-panel">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 34, height: 34, borderRadius: 12,
                    background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: '#031525', fontSize: 16, fontWeight: 800,
                  }}>AI</div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#e0f2fe', letterSpacing: 0.2 }}>AI Suggestions</div>
                    <div style={{ fontSize: 11, color: '#8bb9d8' }}>Smart remediation ideas for failed checks</div>
                  </div>
                </div>
                <button type="button" onClick={() => setShowSuggestions(v => !v)} className="secondary-action">
                  {showSuggestions ? 'Hide AI Suggestions' : 'View AI Suggestions'}
                </button>
              </div>

              {showSuggestions && (
                <div style={{ marginTop: 18, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
                  {result.suggestions.map((item, i) => (
                    <div key={i} className="ai-card">
                      <div style={{ position: 'relative', fontSize: 10, fontWeight: 800, color: '#7dd3fc', marginBottom: 8, letterSpacing: 1 }}>
                        {item.check_id}
                      </div>
                      <div style={{ position: 'relative', fontSize: 12, lineHeight: 1.68, color: '#d8ecf8' }}>
                        {item.suggestion}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="glass-card">
            <div className="section-header">
              <div>
                <div className="section-title">Findings</div>
                <div className="section-subtitle">Detailed HIPAA check results in the same visual system</div>
              </div>
            </div>
            <div className="findings-stack">
              {result.findings.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
