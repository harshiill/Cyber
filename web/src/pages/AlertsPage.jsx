import { useState, useEffect, useMemo } from 'react'
import TopBar from '../components/TopBar'
import http from '../api/http'
import { InfoTip } from '../components/ui'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend,
} from 'recharts'

const FILTERS = ['All', 'Threats', 'Benign']
const BUCKET_OPTIONS = [
  { id: 10,  label: '10s' },
  { id: 30,  label: '30s' },
  { id: 60,  label: '1m' },
  { id: 300, label: '5m' },
]

/* Parse the loose `timestamp` field on alerts. NetworkMonitor emits ISO-ish
   strings like "2026-05-10T12:34:56" but also accepts epoch seconds. */
function parseTimestamp(ts) {
  if (ts == null) return null
  if (typeof ts === 'number') return new Date(ts > 1e12 ? ts : ts * 1000)
  // Try Date.parse on the string
  const t = Date.parse(ts)
  if (!Number.isNaN(t)) return new Date(t)
  return null
}

function bucketAlerts(alerts, bucketSeconds) {
  if (!alerts.length) return []
  const buckets = new Map()  // bucketStartSec -> { attack, benign }
  for (const a of alerts) {
    const d = parseTimestamp(a.timestamp)
    if (!d) continue
    const sec = Math.floor(d.getTime() / 1000)
    const bucket = sec - (sec % bucketSeconds)
    let row = buckets.get(bucket)
    if (!row) { row = { bucket, attack: 0, benign: 0 }; buckets.set(bucket, row) }
    if (a.is_attack) row.attack++; else row.benign++
  }
  // Fill gaps so the X axis is continuous
  const sorted = [...buckets.values()].sort((a, b) => a.bucket - b.bucket)
  if (sorted.length < 2) return sorted.map(formatBucket)
  const out = []
  for (let t = sorted[0].bucket; t <= sorted[sorted.length - 1].bucket; t += bucketSeconds) {
    const found = buckets.get(t)
    out.push(formatBucket(found || { bucket: t, attack: 0, benign: 0 }))
  }
  return out
}

function formatBucket(row) {
  const d = new Date(row.bucket * 1000)
  const label = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  return { ...row, label, total: row.attack + row.benign }
}

function Badge({ isAttack }) {
  return (
    <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: 10, fontWeight: 700,
      background: isAttack ? 'var(--threat-light)' : 'var(--benign-light)',
      color: isAttack ? 'var(--threat)' : 'var(--benign)',
      border: `1px solid ${isAttack ? 'var(--threat-border)' : '#bbf7d0'}` }}>
      {isAttack ? 'ATTACK' : 'BENIGN'}
    </span>
  )
}

export default function AlertsPage() {
  const [alerts, setAlerts]       = useState([])
  const [filter, setFilter]       = useState('All')
  const [loading, setLoading]     = useState(true)
  const [bucketSec, setBucketSec] = useState(30)
  const [showTimeline, setShowTimeline] = useState(true)

  const timeline = useMemo(() => bucketAlerts(alerts, bucketSec), [alerts, bucketSec])

  function load() {
    http.get('/alerts?limit=500')
      .then(r => setAlerts(r.data || []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false))
  }

  async function clearAll() {
    if (!confirm('Clear all alerts from the buffer? Live monitoring continues.')) return
    await http.post('/alerts/clear')
    setAlerts([])
  }

  useEffect(load, [])

  const visible = alerts.filter(a => {
    if (filter === 'Threats') return a.is_attack
    if (filter === 'Benign')  return !a.is_attack && a.prediction !== 'Unclassified'
    return true
  })

  const attacks = alerts.filter(a => a.is_attack).length
  const benign  = alerts.length - attacks

  const pillStyle = active => ({
    padding: '4px 14px', fontSize: 11, fontWeight: 700, cursor: 'pointer', borderRadius: 6, border: 'none',
    background: active ? 'var(--accent)' : 'var(--surface)',
    color: active ? '#fff' : 'var(--text-muted)',
    outline: active ? 'none' : '1px solid var(--border)',
  })

  const th = { padding: '8px 12px', fontSize: 10, fontWeight: 700, color: 'var(--text-faint)',
    textTransform: 'uppercase', letterSpacing: .5, borderBottom: '1px solid var(--border)',
    background: 'var(--surface)', textAlign: 'left' }

  const td = { padding: '7px 12px', fontSize: 11, borderBottom: '1px solid var(--border)',
    fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header bar */}
        <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)',
          padding: '12px 24px', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 6 }}>
            <span style={{ fontSize: 14, fontWeight: 700 }}>Alert History</span>
            <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>
              All flows the monitor classified — newest first. Click rows on the Dashboard for explanations.
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              {FILTERS.map(f => (
                <button key={f} onClick={() => setFilter(f)} style={pillStyle(filter === f)}>{f}</button>
              ))}
            </div>
            <button onClick={load} title="Reload from server"
              style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)',
                border: '1px solid var(--border)', borderRadius: 6, background: 'var(--surface)', cursor: 'pointer' }}>
              Refresh
            </button>
            {alerts.length > 0 && (
              <button onClick={clearAll}
                style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, color: 'var(--threat)',
                  border: '1px solid var(--threat-border)', borderRadius: 6, background: 'var(--surface)', cursor: 'pointer' }}>
                Clear All
              </button>
            )}
            <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: 'var(--threat)', fontWeight: 700 }}>{attacks}</span> attacks ·&nbsp;
              <span style={{ color: 'var(--benign)', fontWeight: 700 }}>{benign}</span> benign ·&nbsp;
              {visible.length} shown
            </span>
          </div>
        </div>

        {/* Timeline */}
        {alerts.length > 0 && (
          <div style={{ background: 'var(--bg)', borderBottom: '1px solid var(--border)',
            padding: '14px 24px', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: showTimeline ? 10 : 0, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 12, fontWeight: 700 }}>
                <InfoTip text="Stacked count of attack vs benign flows over time, bucketed by the chosen interval. Useful to spot bursts and pattern out attack timing.">
                  Attack pattern timeline
                </InfoTip>
              </span>
              <button onClick={() => setShowTimeline(s => !s)}
                style={{ padding: '3px 10px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                  border: '1px solid var(--border)', borderRadius: 5, background: 'var(--surface)', cursor: 'pointer' }}>
                {showTimeline ? 'Hide' : 'Show'}
              </button>
              {showTimeline && (
                <>
                  <span style={{ width: 1, height: 16, background: 'var(--border)' }} />
                  <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Bucket:</span>
                  <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                    {BUCKET_OPTIONS.map(b => (
                      <button key={b.id} onClick={() => setBucketSec(b.id)}
                        style={{ padding: '3px 10px', fontSize: 10, fontWeight: 600, cursor: 'pointer', border: 'none',
                          background: bucketSec === b.id ? 'var(--accent)' : 'transparent',
                          color: bucketSec === b.id ? '#fff' : 'var(--text-muted)' }}>
                        {b.label}
                      </button>
                    ))}
                  </div>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-faint)' }}>
                    {timeline.length} bucket{timeline.length === 1 ? '' : 's'} · {alerts.length} alerts
                  </span>
                </>
              )}
            </div>

            {showTimeline && timeline.length > 0 && (
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={timeline} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
                  <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 9, fill: 'var(--text-faint)' }}
                    interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 9, fill: 'var(--text-faint)' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }}
                    formatter={(v, n) => [v.toLocaleString(), n === 'attack' ? 'Attacks' : 'Benign']} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Bar dataKey="benign" stackId="t" fill="#059669" name="Benign" />
                  <Bar dataKey="attack" stackId="t" fill="#dc2626" name="Attacks" />
                </BarChart>
              </ResponsiveContainer>
            )}

            {showTimeline && timeline.length === 0 && (
              <p style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                Alerts have no parseable timestamps.
              </p>
            )}
          </div>
        )}

        {/* Table */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading
            ? <p style={{ padding: 40, color: 'var(--text-faint)', fontSize: 12 }}>Loading…</p>
            : alerts.length === 0
              ? <p style={{ padding: 40, color: 'var(--text-faint)', fontSize: 12 }}>No alerts yet. Start a PCAP replay or live capture on the Dashboard.</p>
              : (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr>
                      <th style={th}>Time</th>
                      <th style={th}>Verdict</th>
                      <th style={th}><InfoTip text="Probability of attack from the classifier (0–100%).">Prob</InfoTip></th>
                      <th style={th}>Src IP</th>
                      <th style={th}>Src Port</th>
                      <th style={th}>Dst IP</th>
                      <th style={th}>Dst Port</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map(a => (
                      <tr key={a.id} style={{ background: a.is_attack ? 'var(--threat-light)' : 'transparent' }}>
                        <td style={td}>{a.timestamp || '—'}</td>
                        <td style={{ ...td, paddingTop: 5, paddingBottom: 5 }}><Badge isAttack={a.is_attack} /></td>
                        <td style={{ ...td, color: a.is_attack ? 'var(--threat)' : 'var(--benign)', fontWeight: 700 }}>
                          {(a.attack_prob * 100).toFixed(1)}%
                        </td>
                        <td style={td}>{a.src_ip || '—'}</td>
                        <td style={td}>{a.src_port ?? '—'}</td>
                        <td style={td}>{a.dst_ip || '—'}</td>
                        <td style={td}>{a.dst_port ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
          }
        </div>
      </div>
    </div>
  )
}
