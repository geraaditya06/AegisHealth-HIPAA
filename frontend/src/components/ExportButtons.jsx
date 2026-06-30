/**
 * ExportButtons — PDF / JSON / CSV export trigger row.
 *
 * `onExport(format)` is invoked with 'pdf' | 'json' | 'csv'. The parent owns the
 * actual download (so the same component works for scans and tool results).
 */
import { useState } from 'react'

export default function ExportButtons({ onExport, label = 'Export' }) {
  const [busy, setBusy] = useState('')

  async function handle(fmt) {
    setBusy(fmt)
    try { await onExport(fmt) } catch { /* surfaced by parent */ }
    setBusy('')
  }

  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ fontSize: 11, color: 'var(--text2)' }}>{label}:</span>
      {['pdf', 'json', 'csv'].map(fmt => (
        <button key={fmt} onClick={() => handle(fmt)} disabled={!!busy} className="secondary-action" style={{ fontSize: 11, padding: '5px 12px' }}>
          {busy === fmt ? '…' : fmt.toUpperCase()}
        </button>
      ))}
    </div>
  )
}
