import { useState, useEffect } from 'react'
import http from '../api/http'

const VM_IFACE = 'VMware Host-Only (Kali)'

export default function ModeToggle({ onStarted, onStopped, running }) {
  const [iface, setIface]       = useState('')
  const [interfaces, setIfaces] = useState([])
  const [thresh, setThresh]     = useState(0.5)
  const [replayDs, setReplayDs] = useState('2017')
  const [replayModel, setReplayModel] = useState('2017')
  const [runAll, setRunAll]     = useState(false)
  const [order, setOrder]       = useState('random')
  const [err, setErr]           = useState(null)

  useEffect(() => {
    http.get('/monitor/interfaces')
      .then(r => {
        const list = r.data.interfaces || []
        setIfaces([VM_IFACE, ...list])
        setIface(VM_IFACE)
      })
      .catch(() => { setIfaces([VM_IFACE]); setIface(VM_IFACE) })
  }, [])

  useEffect(() => {
    http.get('/model').then(({ data }) => {
      if (data.dataset === '2017' || data.dataset === '2018') {
        setReplayModel(data.dataset)
        setReplayDs(data.dataset)
      }
    }).catch(() => {})
  }, [])

  async function handleStart() {
    setErr(null)
    try {
      if (iface === VM_IFACE) {
        await http.post('/monitor/remote/start')
      } else {
        await http.post('/monitor/start', { interface: iface, threshold: thresh })
      }
      onStarted?.()
    } catch (e) {
      setErr(e.response?.data?.detail || 'Failed to start monitor.')
    }
  }

  async function handleStop() {
    await http.post('/monitor/stop')
    onStopped?.()
  }

  async function handleReplay() {
    setErr(null)
    try {
      const rate = runAll ? 0.05 : 0.6   // rip through the full set; relaxed for the small demo
      await http.post(
        `/monitor/replay?n=40&dataset=${replayDs}&model=${replayModel}` +
        `&full=${runAll}&order=${order}&rate=${rate}`,
      )
      onStarted?.()
    } catch (e) {
      setErr(e.response?.data?.detail || 'Failed to start demo replay.')
    }
  }

  const isCross = replayModel !== replayDs

  const inputStyle = {
    padding: '5px 8px', fontSize: 11, fontFamily: 'var(--font-mono)',
    border: '1px solid var(--border)', borderRadius: 6,
    background: 'var(--surface)', color: 'var(--text)',
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>Capture / remote input</span>

      {interfaces.length > 0 ? (
        <select value={iface} onChange={e => setIface(e.target.value)} disabled={running}
          style={{ ...inputStyle, cursor: 'pointer' }}>
          {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
        </select>
      ) : (
        <input value={iface} onChange={e => setIface(e.target.value)} disabled={running}
          placeholder="Interface name…" style={{ ...inputStyle, width: 160 }} />
      )}

      <span style={{ fontSize: 10, color: 'var(--text-faint)', marginLeft: 4 }}>Threshold:</span>
      <input type="range" min={0.1} max={0.9} step={0.05} value={thresh}
        onChange={e => setThresh(+e.target.value)} disabled={running} style={{ width: 90 }} />
      <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', minWidth: 36 }}>
        {thresh.toFixed(2)}
      </span>

      {!running
        ? <button onClick={handleStart}
            style={{ padding: '5px 16px', background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12, cursor: 'pointer' }}>
            Start
          </button>
        : <button onClick={handleStop}
            style={{ padding: '5px 16px', background: 'var(--threat)', color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12, cursor: 'pointer' }}>
            Stop
          </button>
      }

      {!running && (
        <>
          <span style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 4px' }} />
          <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Model:</span>
          <select value={replayModel} onChange={e => setReplayModel(e.target.value)}
            title="Which trained model classifies the traffic"
            style={{ ...inputStyle, cursor: 'pointer' }}>
            <option value="2017">2017</option>
            <option value="2018">2018</option>
          </select>
          <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Traffic:</span>
          <select value={replayDs} onChange={e => setReplayDs(e.target.value)}
            title="Which dataset's traffic to replay"
            style={{ ...inputStyle, cursor: 'pointer' }}>
            <option value="2017">2017</option>
            <option value="2018">2018</option>
          </select>
          <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Order:</span>
          <select value={order} onChange={e => setOrder(e.target.value)}
            title="Stream flows shuffled, or in the dataset's stored order"
            style={{ ...inputStyle, cursor: 'pointer' }}>
            <option value="random">Random</option>
            <option value="sequential">Dataset order</option>
          </select>
          <label style={{ fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}
            title="Stream the entire dataset instead of a 40-flow sample. Use Stop to halt at any time.">
            <input type="checkbox" checked={runAll} onChange={e => setRunAll(e.target.checked)} />
            Whole dataset
          </label>
          <button onClick={handleReplay}
            title={isCross
              ? `Cross-dataset test: run the CIC-IDS${replayModel} model against CIC-IDS${replayDs} traffic to show cross-version generalisation, with live SHAP/LIME.`
              : 'Replay labeled dataset rows. IP addresses are not included.'}
            style={{ padding: '5px 16px', background: 'var(--surface)', color: 'var(--accent)',
              border: '1px solid var(--accent-border)', borderRadius: 6, fontWeight: 700, fontSize: 12, cursor: 'pointer' }}>
            ▶ Play Dataset
          </button>
          {isCross && (
            <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--amber, #d97706)' }}
              title="The model and the traffic are from different dataset versions.">
              cross-dataset
            </span>
          )}
        </>
      )}
      {err && <span style={{ fontSize: 10, color: 'var(--threat)' }}>{err}</span>}
    </div>
  )
}
