import TopBar from '../components/TopBar'
import KpiCards from '../components/KpiCards'
import TrafficChart from '../components/TrafficChart'
import LiveTrafficChart from '../components/LiveTrafficChart'
import DonutChart from '../components/DonutChart'
import AlertTable from '../components/AlertTable'
import SuspiciousIPs from '../components/SuspiciousIPs'
import BlockedIPs from '../components/BlockedIPs'
import ShapPanel from '../components/ShapPanel'
import StatusBar from '../components/StatusBar'
import ModeToggle from '../components/ModeToggle'
import WelcomeBanner from '../components/WelcomeBanner'
import { useAlerts } from '../hooks/useAlerts'
import { useStats } from '../hooks/useStats'
import { useModel } from '../hooks/useModel'
import http from '../api/http'

function SessionPanel({ stats }) {
  const up = stats.uptime_seconds || 0
  const uptime = up >= 60 ? `${Math.floor(up / 60)}m ${up % 60}s` : `${up}s`
  const rows = [
    ['Total flows',    (stats.total_flows || 0).toLocaleString()],
    ['Threat rate',    `${((stats.threat_rate || 0) * 100).toFixed(1)}%`],
    ['Avg confidence', `${((stats.avg_confidence || 0) * 100).toFixed(1)}%`],
    ['Uptime',         uptime],
  ]
  return (
    <div className="surface panel" style={{ display: 'flex', flexDirection: 'column', gap: 10, justifyContent: 'center' }}>
      <span className="label" style={{ alignSelf: 'flex-start' }}>Session</span>
      {rows.map(([l, v]) => (
        <div key={l} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          fontSize: 11, color: 'var(--text-muted)', width: '100%' }}>
          <span>{l}</span>
          <strong style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>{v}</strong>
        </div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { alerts, selectedId, selectAlert, wsError, wsState, clearLocal } = useAlerts()
  const stats = useStats()
  const { status, modelInfo } = useModel()
  const running = Boolean(stats.running)

  async function handleClear() {
    await http.post('/alerts/clear')
    clearLocal?.()
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg)' }}>
      <TopBar running={running} mode={stats.mode} source={stats.source} />

      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '10px 24px',
        display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <ModeToggle running={running} />
        {wsError && <span style={{ fontSize: 11, color: 'var(--threat)' }}>{wsError}</span>}
        {wsState === 'closed' && (
          <span style={{ fontSize: 10, color: 'var(--amber)', fontWeight: 600,
            background: 'var(--amber-light)', border: '1px solid var(--amber-border)',
            padding: '2px 8px', borderRadius: 99 }}>
            ⚠ Reconnecting…
          </span>
        )}
      </div>

      <WelcomeBanner modelLoaded={!!modelInfo?.loaded} hasAlerts={alerts.length > 0} />

      <KpiCards stats={stats} />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1, overflowY: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 240px', gap: 1, background: 'var(--border)', minHeight: 280 }}>
          <TrafficChart history={stats.traffic_history} labels={stats.traffic_labels} />
          <DonutChart attacks={stats.attacks} benign={stats.benign} unclassified={stats.unclassified || 0} />
          <AlertTable alerts={alerts} selectedId={selectedId} onSelect={selectAlert} onClear={handleClear} />
          <SessionPanel stats={stats} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 1, background: 'var(--border)' }}>
          <LiveTrafficChart history={stats.traffic_history} labels={stats.traffic_labels} />
          <SuspiciousIPs alerts={alerts} />
          <BlockedIPs />
        </div>
      </div>

      <ShapPanel key={selectedId || 'none'} selectedId={selectedId} onClose={() => selectAlert(null)} />
      <StatusBar modelFile={status?.model_file} source={stats.source} stats={stats} />
    </div>
  )
}
