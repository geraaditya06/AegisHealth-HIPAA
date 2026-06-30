/**
 * ExecutiveRisk — board-level risk summary.
 *
 * Renders the executive risk analysis payload: overall/business/technical/
 * compliance risk gauges, Top 10 priorities, Quick Wins and Long-term
 * Improvements. Matches the dark cockpit design.
 */
const riskColor = level => ({
  Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b', Low: '#22c55e',
}[level] || '#38bdf8')

function RiskTile({ label, data }) {
  if (!data) return null
  const color = riskColor(data.level)
  return (
    <div className="glass-card" style={{ padding: 16, flex: '1 1 160px' }}>
      <div style={{ fontSize: 11, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 800, color, marginTop: 6 }}>{data.level}</div>
      <div style={{ height: 6, borderRadius: 99, background: 'rgba(125,211,252,0.08)', marginTop: 8 }}>
        <div style={{ width: `${data.score}%`, height: '100%', borderRadius: 99, background: color }} />
      </div>
      <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 6 }}>Risk index {data.score}/100</div>
    </div>
  )
}

function PriorityList({ title, items, emptyText }) {
  return (
    <div className="glass-card" style={{ flex: '1 1 280px' }}>
      <div className="section-header"><div><div className="section-title" style={{ fontSize: 14 }}>{title}</div></div></div>
      {(!items || items.length === 0) ? (
        <div className="empty-state" style={{ padding: 16 }}>{emptyText}</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
          {items.map((p, i) => {
            const c = riskColor(['critical', 'high'].includes((p.severity || '').toLowerCase()) ? 'Critical' : 'Medium')
            return (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span className="table-pill" style={{ fontSize: 9, color: c, background: `${c}18`, minWidth: 70, textAlign: 'center' }}>{p.check_id}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: 'var(--text)' }}>{p.title}</div>
                  <div style={{ fontSize: 10, color: 'var(--text2)', marginTop: 2 }}>
                    {p.category} · −{p.estimated_risk_reduction}% risk · {p.owasp_category}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default function ExecutiveRisk({ analysis }) {
  if (!analysis) return null
  return (
    <div className="glass-card">
      <div className="section-header">
        <div>
          <div className="section-title">Executive Risk Analysis</div>
          <div className="section-subtitle">
            {analysis.summary?.open_findings ?? 0} open of {analysis.summary?.total_findings ?? 0} findings
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 12 }}>
        <RiskTile label="Overall Risk" data={analysis.overall_risk} />
        <RiskTile label="Business Risk" data={analysis.business_risk} />
        <RiskTile label="Technical Risk" data={analysis.technical_risk} />
        <RiskTile label="Compliance Risk" data={analysis.compliance_risk} />
      </div>

      <div style={{ marginTop: 14 }}>
        <PriorityList title="🎯 Top 10 Priorities" items={analysis.top_10_priorities} emptyText="No open priorities — well done." />
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 14 }}>
        <PriorityList title="⚡ Quick Wins" items={analysis.quick_wins} emptyText="No quick wins identified." />
        <PriorityList title="🏗️ Long-term Improvements" items={analysis.long_term_improvements} emptyText="No long-term items identified." />
      </div>
    </div>
  )
}
