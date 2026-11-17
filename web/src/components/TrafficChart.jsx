import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function TrafficChart({ history, labels }) {
  const data = (history || []).map((v, i) => ({ t: (labels || [])[i] || '', v }))
  return (
    <div className="surface panel">
      <div className="panel-header">
        <span className="label">Observed flows per second</span>
      </div>
      <ResponsiveContainer width="100%" height={140}>
        <BarChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
          <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--text-xfaint)', fontFamily: 'var(--font-mono)' }} interval="preserveStartEnd" />
          <YAxis tick={{ fontSize: 9, fill: 'var(--text-xfaint)' }} />
          <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: '1px solid var(--border)' }} />
          <Bar dataKey="v" fill="#93c5fd" radius={[3,3,0,0]} maxBarSize={24} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
