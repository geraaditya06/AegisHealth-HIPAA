/**
 * CategoryScores — renders the multi-category compliance breakdown.
 *
 * Expects the `breakdown` prop shaped like the backend
 * `scorer.build_score_breakdown` output:
 *   { overall: { score, rating }, categories: { <name>: { score, rating, passed, failed, deductions } } }
 *
 * Each category shows its score ring, pass/fail counts, and an expandable list
 * explaining the point deductions. Styling matches the existing dark cockpit
 * design (glass-card, cyan accents, score color convention).
 */
import { useState } from 'react'

const scoreColor = s => s >= 85 ? '#22c55e' : s >= 60 ? '#f59e0b' : '#ef4444'

function CategoryCard({ name, data }) {
  const [open, setOpen] = useState(false)
  const color = scoreColor(data.score)
  const hasDeductions = (data.deductions || []).length > 0

  return (
    <div className="glass-card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 48, height: 48, borderRadius: '50%', flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 15, fontWeight: 800, color,
          background: `conic-gradient(${color} ${data.score * 3.6}deg, rgba(125,211,252,0.08) 0deg)`,
        }}>
          <div style={{
            width: 38, height: 38, borderRadius: '50%', background: 'var(--surface)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13,
          }}>{data.score}</div>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{name}</div>
          <div style={{ fontSize: 11, color: 'var(--text2)' }}>
            {data.passed} passed · {data.failed} failed
          </div>
        </div>
        <span className="table-pill" style={{ color, background: `${color}18`, fontSize: 10 }}>
          {data.rating}
        </span>
      </div>

      {hasDeductions && (
        <>
          <button
            type="button"
            onClick={() => setOpen(v => !v)}
            className="secondary-action"
            style={{ marginTop: 12, fontSize: 11, padding: '5px 12px' }}
          >
            {open ? 'Hide deductions' : `Why −${100 - data.score} points?`}
          </button>
          {open && (
            <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {data.deductions.map((d, i) => (
                <div key={i} style={{
                  fontSize: 11, color: 'var(--text2)', lineHeight: 1.5,
                  paddingLeft: 10, borderLeft: `2px solid ${scoreColor(0)}55`,
                }}>
                  <strong style={{ color: '#7dd3fc' }}>{d.check_id}</strong>
                  {' '}<span style={{ color: scoreColor(d.points >= 5 ? 0 : 70) }}>(−{d.points})</span>
                  {' '}{d.description}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function CategoryScores({ breakdown }) {
  if (!breakdown?.categories) return null
  const categories = Object.entries(breakdown.categories)

  return (
    <div className="glass-card">
      <div className="section-header">
        <div>
          <div className="section-title">Compliance Categories</div>
          <div className="section-subtitle">
            Per-domain scores with explained deductions
            {breakdown.overall ? ` · Overall ${breakdown.overall.score}/100 (${breakdown.overall.rating})` : ''}
          </div>
        </div>
      </div>
      <div style={{
        marginTop: 14, display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12,
      }}>
        {categories.map(([name, data]) => (
          <CategoryCard key={name} name={name} data={data} />
        ))}
      </div>
    </div>
  )
}
