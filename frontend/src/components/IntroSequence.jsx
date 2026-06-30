import { useEffect } from 'react'

export default function IntroSequence({ onComplete }) {
  useEffect(() => {
    // Total intro duration is 4.5 seconds for a classy fade.
    const timer = setTimeout(() => {
      onComplete()
    }, 4500)

    return () => clearTimeout(timer)
  }, [onComplete])

  return (
    <div className="intro-classy-screen">
      <div className="intro-classy-orb orb-1" />
      <div className="intro-classy-orb orb-2" />
      
      <div className="intro-classy-content">
        <div className="intro-classy-brand">AegisHealth</div>
        <div className="intro-classy-line" />
        <div className="intro-classy-sub">Secure AI Compliance</div>
      </div>
    </div>
  )
}

