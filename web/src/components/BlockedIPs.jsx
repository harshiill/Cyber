import { useState, useEffect, useCallback } from 'react'
import http from '../api/http'

function fmt(ts) {
  if (!ts) return '—'
  try { return new Date(ts * 1000).toLocaleString() } catch { return ts }
}

function Countdown({ blockedAt, ttlSeconds }) {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  if (!ttlSeconds || !blockedAt) return <span style={{ color: 'var(--text-faint)' }}>∞</span>
  const remaining = Math.max(0, Math.round((blockedAt * 1000 + ttlSeconds * 1000 - now) / 1000))
  if (remaining === 0) return <span style={{ color: 'var(--threat)', fontWeight: 700 }}>Expired</span>
  const m = Math.floor(remaining / 60), s = remaining % 60
  return <span className="mono" style={{ fontSize: 10 }}>{m}:{String(s).padStart(2, '0')}</span>
}

export default function BlockedIPs() {
  const [blocked, setBlocked] = useState([])
  const [mode, setMode] = useState(null)
  const [loading, setLoading] = useState(true)
  const [unblocking, setUnblocking] = useState({})
  const [error, setError] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [bRes, mRes] = await Promise.allSettled([
        http.get('/blocked'),
        http.get('/prevention/mode'),
      ])
      if (bRes.status === 'fulfilled') setBlocked(bRes.value.data?.blocked ?? [])
      if (mRes.status === 'fulfilled') setMode(mRes.value.data?.mode ?? null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 10_000)
    return () => clearInterval(id)
  }, [fetchData])

  async function handleUnblock(ip) {
    setUnblocking(u => ({ ...u, [ip]: true }))
    try {
      setError(null)
      const response = await http.post(`/unblock/${encodeURIComponent(ip)}`)
      if (response.data?.action === 'failed') {
        setError(response.data.reason || 'Unable to remove the block.')
      } else {
        setBlocked(b => b.filter(r => r.ip !== ip))
      }
    } catch (e) {
      setError(e.response?.data?.detail || 'Unable to remove the block.')
    } finally {
      setUnblocking(u => ({ ...u, [ip]: false }))
    }
  }

  return (
    <div className="surface panel" style={{ overflow: 'hidden' }}>
      <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="label">Prevention actions</span>
        {mode && (
          <span style={{
            fontSize: 9, fontWeight: 700, padding: '2px 8px',
            borderRadius: 'var(--radius-full)', fontFamily: 'var(--font-mono)',
            background: mode === 'enforce' ? 'var(--threat-light)' : 'var(--benign-light)',
            color: mode === 'enforce' ? 'var(--threat)' : 'var(--benign)',
            border: `1px solid ${mode === 'enforce' ? 'var(--threat-border)' : '#bbf7d0'}`,
          }}>
            {mode.toUpperCase()}
          </span>
        )}
      </div>

      {error && <p role="alert" style={{ color: 'var(--threat)', padding: '8px 16px' }}>{error}</p>}
      {loading ? (
        <p style={{ fontSize: 11, color: 'var(--text-faint)', padding: '12px 16px' }}>Loading…</p>
      ) : blocked.length === 0 ? (
        <p style={{ textAlign: 'center', color: 'var(--text-faint)', padding: 24, fontSize: 12 }}>
          No active or simulated blocks.
        </p>
      ) : (
        <div style={{ overflowY: 'auto', maxHeight: 220 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['IP', 'Reason', 'Blocked At', 'TTL', ''].map(h => (
                  <th key={h} className="label" style={{
                    padding: '0 10px 8px', textAlign: 'left',
                    borderBottom: '1px solid var(--border-subtle)',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {blocked.map(row => (
                <tr key={row.ip} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td className="mono" style={{ padding: '6px 10px', fontSize: 10, color: 'var(--threat)' }}>{row.ip}</td>
                  <td style={{ padding: '6px 10px', fontSize: 10, color: 'var(--text-muted)' }}>{row.reason ?? '—'} {row.mode === 'dry_run' ? '(simulated)' : ''}</td>
                  <td className="mono" style={{ padding: '6px 10px', fontSize: 9, color: 'var(--text-faint)' }}>{fmt(row.blocked_at)}</td>
                  <td style={{ padding: '6px 10px' }}>
                    <Countdown blockedAt={row.blocked_at} ttlSeconds={row.ttl} />
                  </td>
                  <td style={{ padding: '6px 10px' }}>
                    <button
                      onClick={() => handleUnblock(row.ip)}
                      disabled={unblocking[row.ip]}
                      style={{
                        padding: '2px 8px', fontSize: 10, fontWeight: 600,
                        border: '1px solid var(--border)', borderRadius: 5,
                        background: 'var(--surface)', color: 'var(--text-muted)',
                        cursor: unblocking[row.ip] ? 'not-allowed' : 'pointer',
                        opacity: unblocking[row.ip] ? 0.6 : 1,
                      }}
                    >
                      {unblocking[row.ip] ? '…' : 'Unblock'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
