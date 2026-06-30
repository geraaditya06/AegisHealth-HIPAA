import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { googleLogin, login, register } from '../api'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isRegister, setIsRegister] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const googleButtonRef = useRef(null)
  const navigate = useNavigate()
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID

  useEffect(() => {
    if (!googleClientId || !googleButtonRef.current) return

    const existingScript = document.querySelector('script[data-google-identity="true"]')
    const initializeGoogle = () => {
      if (!window.google?.accounts?.id || !googleButtonRef.current) return
      googleButtonRef.current.innerHTML = ''
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: async response => {
          setLoading(true)
          setError('')
          try {
            const res = await googleLogin(response.credential)
            localStorage.setItem('token', res.data.token)
            localStorage.setItem('email', res.data.email)
            localStorage.setItem('role', res.data.role)
            localStorage.setItem('needsIntro', 'true')
            navigate('/')
          } catch (err) {
            setError(err.response?.data?.detail || 'Google sign-in failed')
          }
          setLoading(false)
        },
      })
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: 'outline',
        size: 'large',
        text: isRegister ? 'signup_with' : 'signin_with',
        shape: 'pill',
        width: 320,
      })
    }

    if (existingScript) {
      initializeGoogle()
      return
    }

    const script = document.createElement('script')
    script.src = 'https://accounts.google.com/gsi/client'
    script.async = true
    script.defer = true
    script.dataset.googleIdentity = 'true'
    script.onload = initializeGoogle
    document.body.appendChild(script)

    return () => {
      if (googleButtonRef.current) googleButtonRef.current.innerHTML = ''
    }
  }, [googleClientId, isRegister, navigate])

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const fn = isRegister ? register : login
      const res = await fn(email, password)
      localStorage.setItem('token', res.data.token)
      localStorage.setItem('email', res.data.email)
      localStorage.setItem('role', res.data.role)
      localStorage.setItem('needsIntro', 'true')
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Something went wrong')
    }
    setLoading(false)
  }

  return (
    <div className="login-shell">
      <div className="login-ambient login-ambient-a" />
      <div className="login-ambient login-ambient-b" />
      <div className="login-grid" />

      <section className="login-hero">
        <div className="login-copy">
          <div className="login-brand">
            <div className="app-brand-mark" style={{ width: 48, height: 48 }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <defs>
                  <linearGradient id="loginBrandGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#22c55e" />
                  </linearGradient>
                  <filter id="loginBrandGlow">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                </defs>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#loginBrandGrad)" filter="url(#loginBrandGlow)" />
                <circle cx="12" cy="11" r="2.5" fill="#fff" />
              </svg>
            </div>
            <div>
              <div className="app-brand-title" style={{ fontSize: '28px' }}>
                <span className="brand-light">Aegis</span><span className="brand-bold">Health</span>
              </div>
              <div className="app-brand-subtitle" style={{ fontSize: '11px', marginTop: '4px' }}>
                <span className="brand-dot" />Secure Access
              </div>
            </div>
          </div>
          <h1 className="login-title">Protect patient data with a living security cockpit.</h1>
          <p className="login-subtitle">
            Scan healthcare sites, review AI suggestions, and track HIPAA risk from one animated control layer.
          </p>

          <div className="login-stat-row">
            <div className="login-stat-card">
              <span className="login-stat-label">Live Shield</span>
              <strong>28 compliance checks</strong>
            </div>
            <div className="login-stat-card">
              <span className="login-stat-label">Threat View</span>
              <strong>Risk trend forecasting</strong>
            </div>
          </div>
        </div>

        <div className="login-scene">
          <div className="login-orb login-orb-a" />
          <div className="login-orb login-orb-b" />
          <div className="login-orb login-orb-c" />

          <div className="shield-stack">
            <div className="shield-panel shield-panel-top">
              <span className="shield-dot" />
              <span className="shield-dot" />
            </div>
            <div className="shield-core">
              <div className="shield-ring shield-ring-one" />
              <div className="shield-ring shield-ring-two" />
              <div className="shield-face">
                <div className="shield-eyes">
                  <span />
                  <span />
                </div>
                <div className="shield-mouth" />
              </div>
            </div>
            <div className="shield-panel shield-panel-bottom" />
          </div>

          <div className="float-card float-card-left">
            <span>Threat Lens</span>
            <strong>Continuous HIPAA posture</strong>
          </div>
          <div className="float-card float-card-right">
            <span>AI Layer</span>
            <strong>Actionable remediation ideas</strong>
          </div>
        </div>
      </section>

      <section className="login-panel">
        <div className="login-panel-inner">
          <div style={{ textAlign: 'center', marginBottom: 28, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <div className="app-brand-mark" style={{ width: 56, height: 56, marginBottom: 16 }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <defs>
                  <linearGradient id="loginCardGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#22c55e" />
                  </linearGradient>
                  <filter id="loginCardGlow">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                </defs>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#loginCardGrad)" filter="url(#loginCardGlow)" />
                <circle cx="12" cy="11" r="2.5" fill="#fff" />
              </svg>
            </div>
            <div className="app-brand-title" style={{ fontSize: '32px' }}>
              <span className="brand-light">Aegis</span><span className="brand-bold">Health</span>
            </div>
            <div className="app-brand-subtitle" style={{ fontSize: '13px', marginTop: 12, opacity: 0.9, color: '#7ea6ca' }}>
              {isRegister ? 'Create your account' : 'Sign in to your account'}
            </div>
          </div>

          <div className="google-wrap">
            {googleClientId && <div ref={googleButtonRef} />}
          </div>

          {googleClientId && (
            <div className="login-divider">
              <span>or continue with email</span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <input
              type="email" placeholder="Email address" value={email}
              onChange={e => setEmail(e.target.value)} required
              className="login-input"
            />
            <input
              type="password" placeholder="Password" value={password}
              onChange={e => setPassword(e.target.value)} required
              className="login-input"
            />
            {error && <div style={{ color: '#ff6b6b', fontSize: 12 }}>{error}</div>}
            <button type="submit" disabled={loading} className="login-submit">
              {loading ? 'Please wait...' : isRegister ? 'Create Account' : 'Sign In'}
            </button>
          </form>

          <div style={{ textAlign: 'center', marginTop: 22, fontSize: 12, color: '#83a3c4' }}>
            {isRegister ? 'Already have an account?' : "Don't have an account?"}{' '}
            <span onClick={() => setIsRegister(!isRegister)}
              style={{ color: '#7dd3fc', cursor: 'pointer', fontWeight: 700 }}>
              {isRegister ? 'Sign in' : 'Register'}
            </span>
          </div>
        </div>
      </section>
    </div>
  )
}
