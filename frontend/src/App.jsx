import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import ScanHistory from './pages/ScanHistory'
import SecurityTools from './pages/SecurityTools'
import Deploy from './pages/Deploy'
import AuditLogs from './pages/AuditLogs'
import Layout from './components/Layout'
import IntroSequence from './components/IntroSequence'

function PrivateRoute({ children }) {
  return localStorage.getItem('token') ? children : <Navigate to="/login" />
}

function IntroWrapper({ children }) {
  const [showIntro, setShowIntro] = useState(() => {
    return localStorage.getItem('needsIntro') === 'true'
  })

  useEffect(() => {
    if (showIntro) {
      localStorage.removeItem('needsIntro')
    }
  }, [showIntro])

  if (showIntro) {
    return <IntroSequence onComplete={() => setShowIntro(false)} />
  }

  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<PrivateRoute><IntroWrapper><Layout /></IntroWrapper></PrivateRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="history" element={<ScanHistory />} />
        <Route path="tools" element={<SecurityTools />} />
        <Route path="deploy" element={<Deploy />} />
        <Route path="audit" element={<AuditLogs />} />
      </Route>
    </Routes>
  )
}