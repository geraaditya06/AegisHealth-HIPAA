/**
 * FindingCard — renders a single finding with an expandable AI recommendation.
 *
 * If the finding carries a `recommendation` block (from the AI Recommendation
 * Engine), an expandable panel shows Explanation, Business/Technical Impact,
 * HIPAA Rule, OWASP Category, Fix Steps, a Code Example, and the Estimated Risk
 * Reduction. Matches the dark cockpit design.
 */
import { useState } from 'react'

const sevColor = s => ['critical', 'high'].includes(s) ? '#ef4444'
  : ['warning', 'medium'].includes(s) ? '#f59e0b' : '#22c55e'

function Row({ label, children }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: 1, color: '#7dd3fc', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ fontSize: 12, color: '#d8ecf8', lineHeight: 1.55, marginTop: 2 }}>{children}</div>
    </div>
  )
}

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  const c = sevColor(finding.severity)
  const rec = finding.recommendation

  return (
    <div className="finding-card" style={{ background: `${c}12`, border: `1px solid ${c}30`, flexDirection: 'column', alignItems: 'stretch' }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: `${c}25`, color: c, flexShrink: 0, marginTop: 2, height: 'fit-content' }}>{finding.check_id}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: finding.passed ? '#22c55e' : 'var(--text)' }}>
            {finding.passed ? '✓' : '✗'} {finding.description}
          </div>
          {!finding.passed && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>→ {finding.remediation}</div>}
        </div>
        {rec && !finding.passed && (
          <button onClick={() => setOpen(v => !v)} className="secondary-action" style={{ fontSize: 10, padding: '4px 10px', height: 'fit-content', whiteSpace: 'nowrap' }}>
            {open ? 'Hide' : 'AI Fix'} {rec.estimated_risk_reduction ? `· −${rec.estimated_risk_reduction}% risk` : ''}
          </button>
        )}
      </div>

      {open && rec && (
        <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${c}25` }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
            <span className="table-pill" style={{ fontSize: 10, color: '#a78bfa', background: '#a78bfa18' }}>HIPAA: {rec.hipaa_rule}</span>
            <span className="table-pill" style={{ fontSize: 10, color: '#38bdf8', background: '#38bdf818' }}>OWASP: {rec.owasp_category}</span>
            <span className="table-pill" style={{ fontSize: 10, color: '#f59e0b', background: '#f59e0b18' }}>Effort: {rec.effort}</span>
            <span className="table-pill" style={{ fontSize: 10, color: '#22c55e', background: '#22c55e18' }}>Risk reduction: {rec.estimated_risk_reduction}%</span>
          </div>
          <Row label="Business Impact">{rec.business_impact}</Row>
          <Row label="Technical Impact">{rec.technical_impact}</Row>
          <Row label="Fix Steps">
            <ol style={{ margin: '4px 0 0 16px', padding: 0 }}>
              {rec.fix_steps.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
            </ol>
          </Row>
          {rec.code_example && (
            <Row label={`Code Example — ${rec.code_example.label}`}>
              <pre style={{
                margin: '4px 0 0', padding: 10, borderRadius: 8, overflowX: 'auto',
                background: 'rgba(0,0,0,0.35)', border: '1px solid var(--border)',
                fontSize: 11, color: '#9fe8c4', fontFamily: '"IBM Plex Mono", monospace',
              }}>{rec.code_example.code}</pre>
            </Row>
          )}
        </div>
      )}
    </div>
  )
}
