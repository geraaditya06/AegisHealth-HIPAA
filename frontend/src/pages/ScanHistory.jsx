/**
 * ScanHistory — enterprise scan history browser.
 *
 * Provides server-side search, filtering (status + severity), sorting
 * (date / score / severity / status) and pagination against
 * `GET /api/scan/list`. Selecting a row loads the full detail (findings +
 * category scores) via `GET /api/scan/{id}` and supports retrying failed
 * scans. Matches the existing dark cockpit design language.
 */
import { useEffect, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { listScans, getScanHistory, getScan, retryScan, cancelScan, exportScan } from '../api'
import CategoryScores from '../components/CategoryScores'
import FindingCard from '../components/FindingCard'
import ExecutiveRisk from '../components/ExecutiveRisk'
import ExportButtons from '../components/ExportButtons'
import { onScanUpdate } from '../lib/scanEvents'

const scoreColor = s => s >= 85 ? '#22c55e' : s >= 60 ? '#f59e0b' : '#ef4444'
const statusColor = s => ({
  completed: '#22c55e', complete: '#22c55e', running: '#38bdf8',
  queued: '#a78bfa', failed: '#ef4444', cancelled: '#f59e0b',
}[s] || '#7a9ab8')

const STATUSES = ['', 'queued', 'running', 'completed', 'failed', 'cancelled']
const SEVERITIES = [['', 'All severities'], ['critical', 'Critical'], ['warning', 'Warning'], ['good', 'Low']]
const SORTS = [['date', 'Date'], ['score', 'Score'], ['severity', 'Severity'], ['status', 'Status']]

export default function ScanHistory() {
  const [params] = useSearchParams()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState(null)

  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [sortBy, setSortBy] = useState('date')
  const [order, setOrder] = useState('desc')
  const [page, setPage] = useState(1)
  const pageSize = 10

  const load = useCallback((background = false) => {
    if (!background) setLoading(true)
    return listScans({ q, status, severity, sort_by: sortBy, order, page, page_size: pageSize })
      .then(res => {
        setItems(res.data.items || [])
        setTotal(res.data.total || 0)
        setPages(res.data.pages || 1)
      })
      .catch(() => loadFallback())   // /api/scan/list unavailable → use recent history
      .finally(() => setLoading(false))
  }, [q, status, severity, sortBy, order, page])

  // Fallback for older backends without /api/scan/list: use the always-present
  // /api/scan/history (last 10) and apply search/status filters client-side.
  function loadFallback() {
    return getScanHistory()
      .then(res => {
        let rows = res.data.scans || []
        if (q) rows = rows.filter(s => (s.url || '').toLowerCase().includes(q.toLowerCase()))
        if (status) {
          rows = rows.filter(s => status === 'completed'
            ? ['complete', 'completed'].includes(s.status)
            : s.status === status)
        }
        rows.sort((a, b) => {
          const dir = order === 'asc' ? 1 : -1
          if (sortBy === 'score') return ((a.score || 0) - (b.score || 0)) * dir
          if (sortBy === 'status') return String(a.status).localeCompare(String(b.status)) * dir
          return (new Date(a.created_at) - new Date(b.created_at)) * dir
        })
        setItems(rows)
        setTotal(rows.length)
        setPages(1)
      })
      .catch(() => { setItems([]); setTotal(0); setPages(1) })
  }

  // Reload when filters/sort/page change (with spinner).
  useEffect(() => { load() }, [load])

  // Live synchronization: refresh (without spinner flicker) when a scan changes
  // state and when the window regains focus.
  useEffect(() => {
    const unsub = onScanUpdate(() => load(true))
    const onFocus = () => load(true)
    window.addEventListener('focus', onFocus)
    return () => { unsub(); window.removeEventListener('focus', onFocus) }
  }, [load])

  // While any scan is in flight, poll so the table reflects status transitions.
  useEffect(() => {
    const hasActive = items.some(s => ['queued', 'running'].includes(s.status))
    if (!hasActive) return undefined
    const t = setInterval(() => load(true), 4000)
    return () => clearInterval(t)
  }, [items, load])

  // Deep-link support: ?scan=<id> opens the detail panel.
  useEffect(() => {
    const id = params.get('scan')
    if (id) openDetail(Number(id))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function openDetail(id) {
    try {
      const res = await getScan(id, true)   // enrich → recommendations + risk analysis
      setDetail(res.data)
    } catch { /* ignore */ }
  }

  async function handleRetry(id, e) {
    e.stopPropagation()
    try { await retryScan(id); load(true) } catch { /* ignore */ }
  }

  async function handleCancel(id, e) {
    e.stopPropagation()
    try { await cancelScan(id); load(true) } catch { /* ignore */ }
  }

  return (
    <div className="page-shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="page-kicker">Scan History</span>
          <h1 className="page-title">Every scan, searchable and auditable.</h1>
          <p className="page-subtitle">Search, filter, sort and page through your full compliance scan history.</p>
        </div>
        <div className="hero-stat-grid">
          <div className="hero-stat-card"><span>Total Scans</span><strong>{total}</strong></div>
          <div className="hero-stat-card"><span>View Mode</span><strong>Server-side paging</strong></div>
        </div>
      </section>

      {/* Filter bar */}
      <div className="glass-card" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="scan-box-input" style={{ flex: '1 1 220px', minWidth: 180 }}
          placeholder="Search by URL…"
          value={q}
          onChange={e => { setPage(1); setQ(e.target.value) }}
        />
        <select className="filter-select" value={status} onChange={e => { setPage(1); setStatus(e.target.value) }}>
          {STATUSES.map(s => <option key={s} value={s}>{s ? s[0].toUpperCase() + s.slice(1) : 'All statuses'}</option>)}
        </select>
        <select className="filter-select" value={severity} onChange={e => { setPage(1); setSeverity(e.target.value) }}>
          {SEVERITIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select className="filter-select" value={sortBy} onChange={e => setSortBy(e.target.value)}>
          {SORTS.map(([v, l]) => <option key={v} value={v}>Sort: {l}</option>)}
        </select>
        <button className="secondary-action" onClick={() => setOrder(o => o === 'asc' ? 'desc' : 'asc')}>
          {order === 'asc' ? '↑ Asc' : '↓ Desc'}
        </button>
      </div>

      {/* Results table */}
      <div className="glass-card">
        <div className="section-header">
          <div>
            <div className="section-title">Results</div>
            <div className="section-subtitle">{loading ? 'Loading…' : `${total} scan(s)`}</div>
          </div>
        </div>
        {loading ? (
          <div className="empty-state">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty-state">No scans match your filters.</div>
        ) : (
          <div className="dash-table-wrap">
            <table className="dash-table">
              <thead>
                <tr>{['URL', 'Score', 'Status', 'Date', 'Actions'].map(h => <th key={h}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {items.map(s => (
                  <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(s.id)}>
                    <td><span className="dash-table-url">{s.url}</span></td>
                    <td><span className="dash-table-score" style={{ color: scoreColor(s.score) }}>{s.score ?? '—'}</span></td>
                    <td>
                      <span className="dash-table-pill" style={{
                        color: statusColor(s.status), background: `${statusColor(s.status)}14`,
                        borderColor: `${statusColor(s.status)}30`,
                      }}>{s.status}</span>
                    </td>
                    <td className="dash-table-date">{new Date(s.created_at).toLocaleString()}</td>
                    <td>
                      {['failed', 'cancelled'].includes(s.status) && (
                        <button className="secondary-action" style={{ fontSize: 11, padding: '4px 10px' }} onClick={e => handleRetry(s.id, e)}>Retry</button>
                      )}
                      {['queued', 'running'].includes(s.status) && (
                        <button className="secondary-action" style={{ fontSize: 11, padding: '4px 10px' }} onClick={e => handleCancel(s.id, e)}>Cancel</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pages > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginTop: 16 }}>
            <button className="secondary-action" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>← Prev</button>
            <span style={{ fontSize: 12, color: 'var(--text2)' }}>Page {page} of {pages}</span>
            <button className="secondary-action" disabled={page >= pages} onClick={() => setPage(p => Math.min(pages, p + 1))}>Next →</button>
          </div>
        )}
      </div>

      {/* Detail drawer */}
      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal-panel" onClick={e => e.stopPropagation()}>
            <div className="section-header">
              <div>
                <div className="section-title">{detail.url}</div>
                <div className="section-subtitle">
                  {detail.status} · Score {detail.score ?? '—'} ({detail.rating || 'N/A'})
                </div>
              </div>
              <button className="secondary-action" onClick={() => setDetail(null)}>Close</button>
            </div>

            <div style={{ margin: '10px 0' }}>
              <ExportButtons onExport={(fmt) => exportScan(detail.id, fmt)} />
            </div>

            {detail.category_scores?.categories && (
              <div style={{ marginTop: 12 }}>
                <CategoryScores breakdown={detail.category_scores} />
              </div>
            )}

            {detail.risk_analysis && (
              <div style={{ marginTop: 12 }}>
                <ExecutiveRisk analysis={detail.risk_analysis} />
              </div>
            )}

            <div className="findings-stack" style={{ marginTop: 12 }}>
              {(detail.findings || []).map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
