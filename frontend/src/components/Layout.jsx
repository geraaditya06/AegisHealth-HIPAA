import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import LiveBackground from './LiveBackground'
import NotificationBell from './NotificationBell'
import { logout as apiLogout } from '../api'

const nav = [
  { path: '/', label: 'Dashboard', icon: '▦', hint: 'Live posture' },
  { path: '/scanner', label: 'Scanner', icon: '⬡', hint: 'Run checks' },
  { path: '/history', label: 'Scan History', icon: '◷', hint: 'Search & audit' },
  { path: '/tools', label: 'Security Tools', icon: '⚙', hint: 'Docker & deps' },
  { path: '/deploy', label: 'Deployments', icon: '↑', hint: 'Gate releases' },
  { path: '/audit', label: 'Audit Logs', icon: '◈', hint: 'Track activity' },
]

export default function Layout() {
  const navigate = useNavigate()
  const email = localStorage.getItem('email') || 'devsecops'

  function logout() {
    // Best-effort audit of the logout event, then clear the session.
    apiLogout().catch(() => {}).finally(() => {
      localStorage.clear()
      navigate('/login')
    })
  }

  return (
    <div className="app-shell">
      <LiveBackground />
      <div className="app-ambient app-ambient-one" />
      <div className="app-ambient app-ambient-two" />
      <div className="app-grid" />

      <aside className="app-sidebar">
        <div className="app-brand">
          <div className="app-brand-mark">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <defs>
                <linearGradient id="brandGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" />
                  <stop offset="100%" stopColor="#22c55e" />
                </linearGradient>
                <filter id="brandGlow">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
              </defs>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#brandGrad)" filter="url(#brandGlow)" />
              <circle cx="12" cy="11" r="2" fill="#fff" />
            </svg>
          </div>
          <div>
            <div className="app-brand-title">
              <span className="brand-light">Aegis</span><span className="brand-bold">Health</span>
            </div>
            <div className="app-brand-subtitle">
              <span className="brand-dot" />Secure AI Compliance
            </div>
          </div>
        </div>

        <div className="app-sidebar-section">Command Deck</div>
        <nav className="app-nav">
          {nav.map(item => (
            <NavLink key={item.path} to={item.path} end={item.path === '/'}
              className={({ isActive }) => `app-nav-link${isActive ? ' active' : ''}`}>
              <div className="app-nav-icon">{item.icon}</div>
              <div>
                <div className="app-nav-label">{item.label}</div>
                <div className="app-nav-hint">{item.hint}</div>
              </div>
            </NavLink>
          ))}
        </nav>

        <div className="app-status-card">
          <span className="app-status-kicker">System Mode</span>
          <strong>Live Monitoring</strong>
          <p>AI scoring, deployment checks, and audit visibility in one shielded workflow.</p>
        </div>

        <div className="app-user-card">
          <div className="app-user-avatar">{(email[0] || 'A').toUpperCase()}</div>
          <div style={{ flex: 1 }}>
            <div className="app-user-name">Security Operator</div>
            <div className="app-user-email">{email}</div>
          </div>
          <button onClick={logout} className="app-logout">⏻</button>
        </div>
      </aside>

      <main className="app-main">
        <div className="app-main-stage">
          <div className="app-topbar">
            <div>
              <div className="app-topbar-title">AegisHealth Control Surface</div>
              <div className="app-topbar-subtitle">HIPAA risk intelligence, AI suggestions, and secure release visibility</div>
            </div>
            <div className="app-topbar-badges">
              <span className="app-badge">Live Shield</span>
              <span className="app-badge">AI Workflow</span>
              <NotificationBell />
            </div>
          </div>

          <Outlet />
        </div>
      </main>
    </div>
  )
}
