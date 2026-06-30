/**
 * scanEvents — a tiny in-app pub/sub bus for scan lifecycle changes.
 *
 * Pages that render scan-derived data (Dashboard, Scan History, charts) can
 * subscribe to be notified the instant a scan changes state, so they refresh
 * automatically without a manual page reload. This keeps the existing
 * per-page fetch architecture intact while adding live synchronization.
 *
 * Usage:
 *   import { onScanUpdate, emitScanUpdate } from '../lib/scanEvents'
 *   useEffect(() => onScanUpdate(() => reload()), [reload])   // returns unsubscribe
 *   emitScanUpdate({ type: 'completed', scanId })             // fire from Scanner
 */

const listeners = new Set()

/**
 * Subscribe to scan updates. Returns an unsubscribe function (handy for the
 * React useEffect cleanup contract).
 */
export function onScanUpdate(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Broadcast a scan update to all subscribers. Never throws. */
export function emitScanUpdate(detail = {}) {
  for (const listener of listeners) {
    try { listener(detail) } catch { /* a bad listener must not break others */ }
  }
}
