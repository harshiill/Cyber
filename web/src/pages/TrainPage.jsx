import { useState, useRef, useEffect } from 'react'
import TopBar from '../components/TopBar'
import { PageHeader, MetricCard, InfoTip } from '../components/ui'
import http from '../api/http'
import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from 'recharts'

const DATASETS = ['2017', '2018']
const TRAIN_MODE = 'standard'  // single training mode; balanced speed vs accuracy

function Pill({ active, onClick, children, disabled, sub }) {
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ padding: '8px 16px', fontSize: 11, fontWeight: 700, cursor: disabled ? 'default' : 'pointer', borderRadius: 6,
        background: active ? 'var(--accent)' : 'var(--surface)',
        color:      active ? '#fff' : 'var(--text-muted)',
        border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
        textAlign: 'left', minWidth: 120 }}>
      {children}
      {sub && (
        <span style={{ display: 'block', fontSize: 9, fontWeight: 400, marginTop: 2,
          color: active ? 'rgba(255,255,255,0.75)' : 'var(--text-faint)' }}>
          {sub}
        </span>
      )}
    </button>
  )
}

export default function TrainPage() {
  const [dataset, setDataset] = useState('2017')
  const [source, setSource] = useState('sample')
  const [running, setRunning] = useState(false)
  const [pct, setPct]         = useState(0)
  const [logs, setLogs]       = useState([])
  const [result, setResult]   = useState(null)
  const [err, setErr]         = useState(null)
  const [modelName, setModelName] = useState('')
  const [saveMsg, setSaveMsg]     = useState(null)
  const wsRef  = useRef(null)
  const logRef = useRef(null)

  useEffect(() => () => wsRef.current?.close(), [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  function addLog(msg) {
    setLogs(prev => [...prev, { ts: new Date().toLocaleTimeString(), msg }])
  }

  async function startTraining() {
    setErr(null); setResult(null); setLogs([]); setPct(0)
    const wsHost = window.location.host.includes('5173') ? 'localhost:8000' : window.location.host
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${protocol}://${wsHost}/ws/training`)
    wsRef.current = ws
    setRunning(true)
    ws.onopen = async () => {
      try {
        await http.post('/train', { dataset, mode: TRAIN_MODE, source })
      } catch (e) {
        setErr(e.response?.data?.detail || 'Failed to start training.')
        setRunning(false)
        ws.close()
      }
    }

    ws.onmessage = e => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'progress') {
        setPct(msg.pct || 0)
        addLog(msg.msg)
      } else if (msg.type === 'done') {
        setPct(100)
        addLog(`Done — accuracy ${(msg.test_accuracy * 100).toFixed(2)}%.`)
        setResult(msg)
        setModelName((msg.model_file || '').replace('.joblib', ''))
        setSaveMsg(null)
        setRunning(false)
        ws.close()
      } else if (msg.type === 'error') {
        setErr(msg.msg)
        setRunning(false)
        ws.close()
      }
    }
    ws.onerror = () => { setErr('WebSocket error — check server.'); setRunning(false) }
  }

  async function stopTraining() {
    try {
      await http.post('/train/stop')
      addLog('Stop requested — finishing current step…')
    } catch (e) {
      setErr(e.response?.data?.detail || 'Failed to stop.')
    }
  }

  async function saveModelName() {
    if (!result?.model_file || !modelName.trim()) return
    setSaveMsg(null)
    try {
      const r = await http.post('/models/label', {
        filename: result.model_file, display_name: modelName.trim(),
      })
      setSaveMsg(`Saved as "${r.data.display_name}".`)
    } catch (e) {
      setSaveMsg(e.response?.data?.detail || 'Could not save name.')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />
      <div style={{ flex: 1, padding: '32px 40px', overflowY: 'auto', maxWidth: 980, width: '100%', margin: '0 auto' }}>

        <PageHeader
          title="Train Model"
          subtitle="Fit a Random Forest classifier on a labelled CIC-IDS dataset. The trained model is saved automatically and immediately becomes the active model the dashboard, classifier, and evaluator use."
        />

        {/* Dataset */}
        <div style={{ marginBottom: 24 }}>
          <p className="label" style={{ marginBottom: 8 }}>Dataset</p>
          <div style={{ display: 'flex', gap: 8 }}>
            {DATASETS.map(d => (
              <Pill key={d} active={dataset === d} onClick={() => !running && setDataset(d)} disabled={running}>
                CIC-IDS {d}
              </Pill>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 24 }}>
          <label htmlFor="training-source" className="label">Training data</label>
          <select id="training-source" value={source} disabled={running} onChange={e => setSource(e.target.value)} style={{ marginLeft: 12, padding: 8 }}>
            <option value="sample">Bundled demonstration sample</option>
            <option value="dataset">Full dataset from data/raw</option>
          </select>
          <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>The bundled sample is small; results do not represent the full dataset. Training replaces the saved model for the selected dataset.</p>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
          <button onClick={startTraining} disabled={running}
            style={{ padding: '10px 32px', background: running ? 'var(--border)' : 'var(--accent)',
              color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 13,
              cursor: running ? 'default' : 'pointer' }}>
            {running ? 'Training…' : 'Start Training'}
          </button>
          {running && (
            <button onClick={stopTraining}
              style={{ padding: '10px 24px', background: 'var(--surface)', color: 'var(--threat)',
                border: '1px solid var(--threat-border)', borderRadius: 6, fontWeight: 700, fontSize: 13,
                cursor: 'pointer' }}>
              Stop
            </button>
          )}
        </div>

        {/* Progress bar */}
        {(running || pct > 0) && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Progress</span>
              <span style={{ fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{pct}%</span>
            </div>
            <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: 'var(--accent)', transition: 'width 0.4s ease', borderRadius: 3 }} />
            </div>
          </div>
        )}

        {logs.length > 0 && (
          <div ref={logRef} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6,
            padding: 12, maxHeight: 180, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-muted)', marginBottom: 24, lineHeight: 1.7, textAlign: 'left' }}>
            {logs.map((l, i) => (
              <div key={i}><span style={{ color: 'var(--text-faint)' }}>[{l.ts}]</span> {l.msg}</div>
            ))}
          </div>
        )}

        {err && <p style={{ color: 'var(--threat)', fontSize: 12, marginBottom: 16 }}>{err}</p>}

        {result && (
          <div>
            {/* Save + name the trained model */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, flexWrap: 'wrap',
              background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px' }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)' }}>Save this model as:</span>
              <input value={modelName} onChange={e => setModelName(e.target.value)}
                placeholder="e.g. NIDS 2018 final"
                style={{ padding: '6px 10px', fontSize: 12, border: '1px solid var(--border)', borderRadius: 6,
                  background: 'var(--bg, #fff)', color: 'var(--text)', minWidth: 220 }} />
              <button onClick={saveModelName} disabled={!modelName.trim()}
                style={{ padding: '6px 18px', background: modelName.trim() ? 'var(--accent)' : 'var(--border)',
                  color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12,
                  cursor: modelName.trim() ? 'pointer' : 'default' }}>
                Save name
              </button>
              <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
                File: {result.model_file}
              </span>
              {saveMsg && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--benign, #059669)' }}>{saveMsg}</span>}
            </div>

            <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
              <MetricCard label="Test Accuracy"
                value={`${(result.test_accuracy * 100).toFixed(2)}%`}
                color="var(--benign)" accent
                info="Fraction of test samples classified correctly. Higher is better." />
              <MetricCard label="Precision"
                value={result.test_precision != null ? `${(result.test_precision * 100).toFixed(2)}%` : '—'}
                color="#7c3aed" accent
                info="Of flows flagged as attacks, how many really are attacks. Low = many false alarms." />
              <MetricCard label="Recall"
                value={result.test_recall != null ? `${(result.test_recall * 100).toFixed(2)}%` : '—'}
                color="#dc2626" accent
                info="Of all real attacks, how many were caught. Low = many missed attacks." />
              <MetricCard label="F1-Score"
                value={result.test_f1 != null ? `${(result.test_f1 * 100).toFixed(2)}%` : '—'}
                color="#d97706" accent
                info="Harmonic mean of precision and recall. Best single number for imbalanced classes." />
              <MetricCard label="Train / Test"
                value={`${(result.train_samples / 1000).toFixed(0)}k / ${(result.test_samples / 1000).toFixed(0)}k`}
                color="var(--text-muted)" />
            </div>

            {result.feature_importances?.length > 0 && (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4, textAlign: 'left' }}>
                  <InfoTip text="How much each feature helped the forest split the data. Higher bars = features that mattered most when deciding 'attack vs benign'.">
                    Top Feature Importances
                  </InfoTip>
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14, textAlign: 'left' }}>
                  These are the network traits the model relied on most.
                </p>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={result.feature_importances} layout="vertical" margin={{ left: 20, right: 20 }}>
                    <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-faint)' }} />
                    <YAxis type="category" dataKey="feature" width={160} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                    <Tooltip
                      formatter={v => [v.toFixed(4), 'Importance']}
                      contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                    <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                      {result.feature_importances.map((_, i) => (
                        <Cell key={i} fill={i < 3 ? '#2563eb' : '#93c5fd'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
