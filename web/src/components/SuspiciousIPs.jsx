import { useMemo } from 'react'

const RISK_COLORS = {
  CRITICAL: { background: '#ef4444', color: '#fff' },
  HIGH:     { background: '#f97316', color: '#fff' },
  MEDIUM:   { background: '#eab308', color: '#000' },
  LOW:      { background: '#22c55e', color: '#fff' },
}

function RiskBadge({ level }) {
  const style = RISK_COLORS[level] || RISK_COLORS.LOW
  return (
    <span style={{
      ...style, fontSize: 9, fontWeight: 700, padding: '2px 7px',
      borderRadius: 'var(--radius-full)', fontFamily: 'var(--font-mono)',
      letterSpacing: '0.03em',
    }}>
      {level}
    </span>
  )
}

export default function SuspiciousIPs({ alerts = [] }) {
  const rows = useMemo(() => {
    const map = {}
    for (const a of alerts) {
      const ip = a.src_ip
      if (!ip) continue
      if (!map[ip] || a.risk_score > map[ip].risk_score) {
        map[ip] = {
          ip,
          risk_score: a.risk_score ?? 0,
          risk_level: a.risk_level ?? 'LOW',
          attack_type: a.attack_type ?? a.prediction ?? '—',
          last_seen: a.timestamp,
        }
      } else if (a.timestamp > map[ip].last_seen) {
        map[ip].last_seen = a.timestamp
      }
    }
    return Object.values(map)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 10)
  }, [alerts])

  return (
    <div className="surface panel" style={{ overflow: 'hidden' }}>
      <div className="panel-header">
        <span className="label">Suspicious IPs</span>
      </div>
      <div style={{ overflowY: 'auto', maxHeight: 220 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['IP', 'Risk', 'Attack Type', 'Last Seen'].map(h => (
                <th key={h} className="label" style={{
                  padding: '0 10px 8px', textAlign: 'left',
                  borderBottom: '1px solid var(--border-subtle)',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.ip} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td className="mono" style={{ padding: '6px 10px', fontSize: 10, color: 'var(--text-muted)' }}>{r.ip}</td>
                <td style={{ padding: '6px 10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <RiskBadge level={r.risk_level} />
                    <span className="mono" style={{ fontSize: 9, color: 'var(--text-faint)' }}>{r.risk_score}</span>
                  </div>
                </td>
                <td style={{ padding: '6px 10px', fontSize: 10, color: 'var(--text)' }}>{r.attack_type}</td>
                <td className="mono" style={{ padding: '6px 10px', fontSize: 9, color: 'var(--text-xfaint)' }}>{r.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <p style={{ textAlign: 'center', color: 'var(--text-faint)', padding: 24, fontSize: 12 }}>
            No suspicious IPs detected.
          </p>
        )}
      </div>
    </div>
  )
}
