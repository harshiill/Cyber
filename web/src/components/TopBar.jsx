import { useNavigate, useLocation } from 'react-router-dom'
import { useTheme } from '../hooks/useTheme'

const TABS = [
  { path: '/',         label: 'Dashboard' },
  { path: '/alerts',   label: 'Alerts' },
  { path: '/explain',  label: 'XAI' },
  { path: '/train',    label: 'Train' },
  { path: '/evaluate', label: 'Evaluate' },
  { path: '/classify', label: 'Classify' },
  { path: '/settings', label: 'Settings' },
]

export default function TopBar({ running, mode, source }) {
  const nav = useNavigate()
  const loc = useLocation()
  const { theme, toggle } = useTheme()
  return (
    <div style={{ background: 'var(--surface)', height: 56, display: 'flex', alignItems: 'center',
      gap: 16, padding: '0 24px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
      <span style={{ fontSize: 17, fontWeight: 800, letterSpacing: .8,
        background: 'linear-gradient(90deg,#2563eb,#7c3aed)', WebkitBackgroundClip: 'text',
        WebkitTextFillColor: 'transparent', flexShrink: 0 }}>
        NIDS-XAI
      </span>
      <div style={{ width: 1, height: 20, background: 'var(--border)', flexShrink: 0 }} />
      <nav style={{ display: 'flex', gap: 2 }}>
        {TABS.map(t => (
          <button key={t.path} onClick={() => nav(t.path)}
            style={{ padding: '6px 12px', borderRadius: 6, fontSize: 12,
              fontWeight: loc.pathname === t.path ? 600 : 500,
              border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
              background: loc.pathname === t.path ? 'var(--accent-light)' : 'transparent',
              color: loc.pathname === t.path ? 'var(--accent)' : 'var(--text-muted)' }}>
            {t.label}
          </button>
        ))}
      </nav>
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
        <button onClick={toggle} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{ padding: '4px 8px', fontSize: 13, background: 'transparent', border: '1px solid var(--border)',
            borderRadius: 6, cursor: 'pointer', color: 'var(--text-muted)', lineHeight: 1 }}>
          {theme === 'dark' ? '☀' : '☾'}
        </button>
        {running
          ? <span title={`${mode === 'replay' ? 'Dataset replay' : mode === 'remote' ? 'Remote data' : 'Live capture'}: ${source || ''}`}
              style={{ display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--accent-light)', border: '1px solid var(--accent-border)',
              borderRadius: 'var(--radius-full)', padding: '5px 12px', fontSize: 11,
              fontWeight: 700, color: 'var(--accent)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)', animation: 'blink 1.2s infinite' }} />
              {mode === 'replay' ? 'REPLAY' : mode === 'remote' ? 'REMOTE' : 'MONITORING'} · {source || '…'}
            </span>
          : <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>Idle</span>
        }
      </div>
    </div>
  )
}
