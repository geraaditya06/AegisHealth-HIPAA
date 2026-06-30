/**
 * NotificationBell — topbar in-app notification center.
 *
 * Polls the unread count, shows a dropdown of recent notifications, and lets
 * the user mark items (or all) as read. Clicking a notification navigates to
 * its deep link (e.g. a scan in history). Matches the dark cockpit design.
 */
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  getNotifications, getUnreadCount,
  markNotificationRead, markAllNotificationsRead,
} from '../api'
import { onScanUpdate } from '../lib/scanEvents'

const sevColor = s => ({
  critical: '#ef4444', warning: '#f59e0b', success: '#22c55e', info: '#38bdf8',
}[s] || '#38bdf8')

export default function NotificationBell() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState([])
  const [unread, setUnread] = useState(0)
  const ref = useRef(null)

  function refreshCount() {
    getUnreadCount().then(r => setUnread(r.data.unread_count || 0)).catch(() => {})
  }

  // Poll unread count every 15s for near-real-time badge updates.
  useEffect(() => {
    refreshCount()
    const t = setInterval(refreshCount, 15000)
    // Refresh immediately when a scan completes (scan_complete / critical_finding
    // notifications are created server-side at that moment).
    const unsub = onScanUpdate(() => setTimeout(refreshCount, 500))
    return () => { clearInterval(t); unsub() }
  }, [])

  // Close on outside click.
  useEffect(() => {
    function onClick(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  function toggle() {
    const next = !open
    setOpen(next)
    if (next) {
      getNotifications({ limit: 20 }).then(r => {
        setItems(r.data.notifications || [])
        setUnread(r.data.unread_count || 0)
      }).catch(() => {})
    }
  }

  async function handleClick(n) {
    if (!n.is_read) {
      try { await markNotificationRead(n.id) } catch { /* ignore */ }
      setItems(prev => prev.map(x => x.id === n.id ? { ...x, is_read: true } : x))
      setUnread(u => Math.max(0, u - 1))
    }
    if (n.link) { setOpen(false); navigate(n.link) }
  }

  async function handleMarkAll() {
    try { await markAllNotificationsRead() } catch { /* ignore */ }
    setItems(prev => prev.map(x => ({ ...x, is_read: true })))
    setUnread(0)
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={toggle} className="notif-bell" aria-label="Notifications">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
        {unread > 0 && <span className="notif-badge">{unread > 9 ? '9+' : unread}</span>}
      </button>

      {open && (
        <div className="notif-dropdown">
          <div className="notif-dropdown-head">
            <span>Notifications</span>
            {unread > 0 && <button className="notif-markall" onClick={handleMarkAll}>Mark all read</button>}
          </div>
          <div className="notif-list">
            {items.length === 0 ? (
              <div className="notif-empty">No notifications yet.</div>
            ) : items.map(n => (
              <div
                key={n.id}
                className={`notif-item${n.is_read ? '' : ' unread'}`}
                onClick={() => handleClick(n)}
              >
                <span className="notif-dot" style={{ background: sevColor(n.severity) }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="notif-title">{n.title}</div>
                  {n.message && <div className="notif-msg">{n.message}</div>}
                  <div className="notif-time">{new Date(n.created_at).toLocaleString()}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
