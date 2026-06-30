import { useEffect, useRef } from 'react'

export default function IntroBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let animationFrameId
    const startTime = performance.now()
    
    // Starfield setup
    const stars = []
    const numStars = 400
    
    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()

    for (let i = 0; i < numStars; i++) {
      stars.push({
        x: (Math.random() - 0.5) * canvas.width * 2,
        y: (Math.random() - 0.5) * canvas.height * 2,
        z: Math.random() * 1000,
        radius: Math.random() * 2 + 0.5
      })
    }

    const animate = (time) => {
      ctx.fillStyle = '#040810'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      
      const elapsed = time - startTime
      const cx = canvas.width / 2
      const cy = canvas.height / 2
      
      // Sync timings:
      // Word crash: ~1600ms
      // Zoom starts: ~2800ms
      
      // Base speed
      let speed = 2
      // Warp speed during zoom
      if (elapsed > 2800) {
        speed = 2 + ((elapsed - 2800) / 1000) * 30
      }

      ctx.save()
      ctx.translate(cx, cy)
      
      stars.forEach(star => {
        star.z -= speed
        if (star.z <= 0) {
          star.x = (Math.random() - 0.5) * canvas.width * 2
          star.y = (Math.random() - 0.5) * canvas.height * 2
          star.z = 1000
        }

        const x = (star.x / star.z) * 500
        const y = (star.y / star.z) * 500
        const scale = 1000 / Math.max(star.z, 1)

        ctx.beginPath()
        ctx.arc(x, y, star.radius * scale * 0.2, 0, Math.PI * 2)
        // Cyan & green hyperspace vibe
        ctx.fillStyle = star.x > 0 ? 'rgba(56, 189, 248, 0.8)' : 'rgba(34, 197, 94, 0.8)'
        ctx.fill()
        
        // Warp streaks
        if (speed > 5) {
          const prevZ = star.z + speed
          const prevX = (star.x / prevZ) * 500
          const prevY = (star.y / prevZ) * 500
          ctx.beginPath()
          ctx.moveTo(x, y)
          ctx.lineTo(prevX, prevY)
          ctx.strokeStyle = ctx.fillStyle
          ctx.lineWidth = star.radius * scale * 0.2
          ctx.stroke()
        }
      })
      ctx.restore()

      // Flash at word collision (1600ms)
      if (elapsed >= 1500 && elapsed < 2200) {
        const flashAlpha = 1 - (elapsed - 1500) / 700
        ctx.fillStyle = `rgba(255, 255, 255, ${flashAlpha * 0.6})`
        ctx.fillRect(0, 0, canvas.width, canvas.height)
      }

      animationFrameId = requestAnimationFrame(animate)
    }

    window.addEventListener('resize', resize)
    animationFrameId = requestAnimationFrame(animate)

    return () => {
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(animationFrameId)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0
      }}
    />
  )
}
